#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_VERSION="1.2"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_RELEASE="$(uname -r)"
NAMESPACE="${BPF_SENTINEL_NAMESPACE:-bpf-sentinel-demo}"
POD_NAME="${BPF_SENTINEL_POD:-simulated-attacker}"
CONTAINER_NAME="${BPF_SENTINEL_CONTAINER:-attacker}"
HELPER_FILE="${BPF_SENTINEL_HELPER_FILE:-${SCRIPT_DIR}/bpf-map-test-helper.c}"
SENTINEL_FILE="${BPF_SENTINEL_FILE:-${SCRIPT_DIR}/k8s-aware-BPF-sentinel2.py}"
MAP_DIRECTORY="/sys/fs/bpf/sentinel-demo"
MAP_PATH="${MAP_DIRECTORY}/sentinel_test"
READY_TIMEOUT_SECONDS="${BPF_SENTINEL_READY_TIMEOUT_SECONDS:-360}"

log() {
    printf '\n==> %s\n' "$*"
}

fail() {
    printf '\nERROR: %s\n' "$*" >&2
    exit 1
}

on_error() {
    local exit_code=$?
    printf '\nERROR: setup failed at line %s (exit code %s).\n' \
        "${BASH_LINENO[0]}" "${exit_code}" >&2
    printf 'Inspect the pod with:\n' >&2
    printf '  microk8s kubectl describe pod -n %q %q\n' \
        "${NAMESPACE}" "${POD_NAME}" >&2
    printf '  microk8s kubectl logs -n %q %q -c %q\n' \
        "${NAMESPACE}" "${POD_NAME}" "${CONTAINER_NAME}" >&2
    exit "${exit_code}"
}

trap on_error ERR

command -v microk8s >/dev/null 2>&1 || fail "microk8s is not installed or not in PATH."
command -v sudo >/dev/null 2>&1 || fail "sudo is not installed or not in PATH."
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed or not in PATH."
[[ -f "${HELPER_FILE}" ]] || fail "Missing helper source: ${HELPER_FILE}"
[[ -f "${SENTINEL_FILE}" ]] || fail "Missing Sentinel program: ${SENTINEL_FILE}"

printf '%s\n' \
    "BPF Sentinel laboratory setup script v${SCRIPT_VERSION}" \
    "This script recreates only the disposable ${NAMESPACE}/${POD_NAME} pod," \
    "replaces only ${MAP_PATH}, compiles the test helper, and starts Sentinel." \
    "Do not use the configured map path for a production BPF map."

if [[ "${1:-}" != "--yes" ]]; then
    read -r -p "Continue? [y/N] " answer
    [[ "${answer}" =~ ^[Yy]$ ]] || fail "Cancelled by user."
fi

log "Validating sudo credentials"
sudo -v

log "Checking MicroK8s access"
microk8s status --wait-ready >/dev/null
microk8s kubectl version >/dev/null

log "Creating namespace ${NAMESPACE}"
microk8s kubectl create namespace "${NAMESPACE}" \
    --dry-run=client -o yaml | microk8s kubectl apply -f -

log "Removing any previous disposable pod"
microk8s kubectl delete pod "${POD_NAME}" \
    -n "${NAMESPACE}" --ignore-not-found=true --wait=true

log "Creating the controlled privileged laboratory pod"
microk8s kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${POD_NAME}
  namespace: ${NAMESPACE}
  labels:
    app: bpf-sentinel-test
spec:
  hostPID: true
  restartPolicy: Never
  containers:
    - name: ${CONTAINER_NAME}
      image: ubuntu:24.04
      command:
        - /bin/bash
        - -c
        - |
          set -eu
          apt-get update
          DEBIAN_FRONTEND=noninteractive apt-get install -y \
            gcc clang make \
            linux-tools-${KERNEL_RELEASE} linux-headers-${KERNEL_RELEASE} \
            libbpf-dev libelf-dev zlib1g-dev linux-libc-dev \
            libcap2-bin procps python3
          command -v bpftool >/dev/null
          bpftool version
          touch /tmp/bpf-sentinel-ready
          exec sleep infinity
      securityContext:
        privileged: true
      volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
  volumes:
    - name: bpffs
      hostPath:
        path: /sys/fs/bpf
        type: Directory
EOF

log "Waiting for the pod to enter the Ready state"
microk8s kubectl wait \
    --namespace "${NAMESPACE}" \
    --for=condition=Ready "pod/${POD_NAME}" \
    --timeout="${READY_TIMEOUT_SECONDS}s"

log "Waiting for package installation inside the pod"
deadline=$((SECONDS + READY_TIMEOUT_SECONDS))
until microk8s kubectl exec -n "${NAMESPACE}" "${POD_NAME}" \
    -c "${CONTAINER_NAME}" -- test -f /tmp/bpf-sentinel-ready 2>/dev/null; do
    pod_phase="$(microk8s kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" \
        -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [[ "${pod_phase}" == "Failed" || "${pod_phase}" == "Succeeded" ]]; then
        microk8s kubectl logs -n "${NAMESPACE}" "${POD_NAME}" \
            -c "${CONTAINER_NAME}" >&2 || true
        fail "Pod initialization ended unexpectedly with phase ${pod_phase}."
    fi
    if (( SECONDS >= deadline )); then
        microk8s kubectl logs -n "${NAMESPACE}" "${POD_NAME}" \
            -c "${CONTAINER_NAME}" >&2 || true
        fail "Timed out waiting for package installation."
    fi
    sleep 5
done

log "Copying and compiling the disposable map test helper"
microk8s kubectl cp "${HELPER_FILE}" \
    "${NAMESPACE}/${POD_NAME}:/tmp/bpf-map-test-helper.c" \
    -c "${CONTAINER_NAME}"

microk8s kubectl exec -n "${NAMESPACE}" "${POD_NAME}" \
    -c "${CONTAINER_NAME}" -- \
    gcc -O2 -Wall -Wextra \
    /tmp/bpf-map-test-helper.c \
    -o /tmp/bpf-map-test-helper

log "Replacing only the disposable test map"
microk8s kubectl exec -n "${NAMESPACE}" "${POD_NAME}" \
    -c "${CONTAINER_NAME}" -- \
    sh -eu -c 'map_dir=$1; map_path=$2
        mkdir -p "$map_dir"
        if test -e "$map_path"; then
            unlink "$map_path"
        fi' sh "${MAP_DIRECTORY}" "${MAP_PATH}"

microk8s kubectl exec -n "${NAMESPACE}" "${POD_NAME}" \
    -c "${CONTAINER_NAME}" -- \
    bpftool map create "${MAP_PATH}" \
    type hash key 4 value 4 entries 16 name sentinel_test

log "Verifying the disposable map"
microk8s kubectl exec -n "${NAMESPACE}" "${POD_NAME}" \
    -c "${CONTAINER_NAME}" -- \
    bpftool map show pinned "${MAP_PATH}"

log "Running the Sentinel self test"
python3 "${SENTINEL_FILE}" --self-test

log "Setup complete; starting BPF Sentinel"
printf '%s\n' \
    "Keep this terminal open. Run update, deletion, and freeze tests from a second terminal." \
    "Press Ctrl-C to stop Sentinel."

exec sudo env \
    BPF_SENTINEL_KUBECTL="microk8s kubectl" \
    BPF_SENTINEL_PROTECTED_MAP_NAMES="sentinel_test=SentinelTest" \
    python3 "${SENTINEL_FILE}"
