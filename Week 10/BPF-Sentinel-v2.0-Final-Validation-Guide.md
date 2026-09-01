# BPF Sentinel v2.0 Final Validation Guide

This protocol completes the remaining tests before finalizing the paper. Use only disposable maps in the laboratory namespace.

## Safety and terminal layout

Never test on maps used by Calico, Cilium, Falco, Tetragon, or another live component. Freeze is permanent for one map object, so perform it last and then remove and recreate that disposable map.

Use three terminals:

| Terminal | Purpose |
|---|---|
| A | Sentinel output |
| B | Kubernetes test commands |
| C | Resource measurements |

Begin in `~/cybr599`.

## 1. Create an evidence folder

```bash
cd ~/cybr599
export EVIDENCE_DIR="$HOME/cybr599/evidence/v2.0-final-validation"
mkdir -p "$EVIDENCE_DIR"

date -Is | tee "$EVIDENCE_DIR/start-time.txt"
uname -a | tee "$EVIDENCE_DIR/kernel.txt"
microk8s kubectl version -o yaml > "$EVIDENCE_DIR/kubernetes-version.yaml"
sudo bpftool version | tee "$EVIDENCE_DIR/bpftool-version.txt"

sha256sum \
  k8s-aware-BPF-sentinel2.py \
  bpf-map-test-helper.c \
  setup-and-run-bpf-sentinel.sh \
  | tee "$EVIDENCE_DIR/source-checksums.sha256"
```

## 2. Confirm the pod and helper

```bash
microk8s kubectl get pod simulated-attacker \
  -n bpf-sentinel-demo -o wide \
  | tee "$EVIDENCE_DIR/simulated-attacker-pod.txt"

microk8s kubectl exec \
  -n bpf-sentinel-demo simulated-attacker \
  -c attacker -- \
  test -x /tmp/bpf-map-test-helper \
  && echo "Helper is ready"
```

If either is missing, run:

```bash
chmod +x setup-and-run-bpf-sentinel.sh
./setup-and-run-bpf-sentinel.sh
```

When it reaches `Listening...`, press `Ctrl-C`. Setup is complete.

## 3. Recreate the map that was frozen

Stop Sentinel before recreating the map. Run in Terminal B:

```bash
microk8s kubectl exec \
  -n bpf-sentinel-demo simulated-attacker \
  -c attacker -- \
  sh -eu -c '
    p=/sys/fs/bpf/sentinel-demo/sentinel_test
    test ! -e "$p" || unlink "$p"
    bpftool map create "$p" \
      type hash key 4 value 4 entries 64 \
      name sentinel_test
  '

sudo bpftool map show pinned \
  /sys/fs/bpf/sentinel-demo/sentinel_test \
  | tee "$EVIDENCE_DIR/fresh-protected-map.txt"
```

A new map ID is expected.

## 4. Start a logged Sentinel session

Run in Terminal A:

```bash
cd ~/cybr599
export EVIDENCE_DIR="$HOME/cybr599/evidence/v2.0-final-validation"

sudo env \
  BPF_SENTINEL_KUBECTL="microk8s kubectl" \
  BPF_SENTINEL_PROTECTED_MAP_NAMES="sentinel_test=SentinelTest" \
  python3 -u k8s-aware-BPF-sentinel2.py \
  2>&1 | tee "$EVIDENCE_DIR/sentinel-functional.log"
```

Confirm the banner shows version 2.4.2, configured protection, and `Listening`.

## 5. CAP_BPF, enumeration, and correlation

Run in Terminal B:

```bash
microk8s kubectl exec \
  -n bpf-sentinel-demo simulated-attacker \
  -c attacker -- \
  capsh --caps="cap_bpf+eip" -- -c \
  'bpftool prog show >/dev/null; bpftool map show >/dev/null'
```

Expected evidence includes CAP_BPF activity, BPF program enumeration, BPF map enumeration, and ideally a correlated sequence. Wait for the next statistics line and verify that `correlated_sequences` increases.

If capability assignment fails, preserve this diagnostic:

```bash
microk8s kubectl exec \
  -n bpf-sentinel-demo simulated-attacker \
  -c attacker -- \
  capsh --print \
  | tee "$EVIDENCE_DIR/container-capabilities.txt"
```

If the individual events appear but no sequence forms, repeat the first command once within 60 seconds.

## 6. Host filtering

Note the current statistics, then run on the host:

```bash
sudo bpftool prog show >/dev/null
sudo bpftool map show >/dev/null
```

Pass conditions:

- No Kubernetes attacker alert for these host operations
- `host_filtered` increases
- `k8s_reported` does not increase because of them

Save before and after screenshots.

## 7. Trusted Calico filtering

```bash
microk8s kubectl get pods -A \
  -l k8s-app=calico-node \
  -o custom-columns='NAMESPACE:.metadata.namespace,POD:.metadata.name,CONTAINERS:.spec.containers[*].name' \
  | tee "$EVIDENCE_DIR/calico-identity.txt"
```

Leave Sentinel running for about one minute.

Pass conditions:

- `trusted_filtered` increases
- No individual Calico warning is printed
- Attacker activity remains reportable

This is a negative control for noise suppression.

## 8. Protected versus unprotected classification

Create an unprotected map:

```bash
microk8s kubectl exec \
  -n bpf-sentinel-demo simulated-attacker \
  -c attacker -- \
  sh -eu -c '
    p=/sys/fs/bpf/sentinel-demo/unprotected_test
    test ! -e "$p" || unlink "$p"
    bpftool map create "$p" \
      type hash key 4 value 4 entries 16 \
      name unprot_test
  '
```

Update and inspect it:

```bash
microk8s kubectl exec \
  -n bpf-sentinel-demo simulated-attacker \
  -c attacker -- \
  /tmp/bpf-map-test-helper \
  /sys/fs/bpf/sentinel-demo/unprotected_test \
  update 1 7

sudo bpftool map dump pinned \
  /sys/fs/bpf/sentinel-demo/unprotected_test \
  | tee "$EVIDENCE_DIR/unprotected-map-dump.txt"
```

Expected alert:

```text
RESULT=success
MAP_NAME=unprot_test
PROTECTED=no
SECURITY_TOOL=none
```

`successful_map_mutations` increases by one, but `protected_map_mutations` does not. The separate protected tampering message must not appear.

Remove the map:

```bash
microk8s kubectl exec \
  -n bpf-sentinel-demo simulated-attacker \
  -c attacker -- \
  sh -c 'test ! -e /sys/fs/bpf/sentinel-demo/unprotected_test || unlink /sys/fs/bpf/sentinel-demo/unprotected_test'
```

## 9. Exact attribution in a two container pod

Create the pod:

```bash
microk8s kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: multi-container-test
  namespace: bpf-sentinel-demo
spec:
  restartPolicy: Never
  containers:
    - name: attacker
      image: ubuntu:24.04
      command: ["/bin/sh", "-c", "sleep infinity"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
    - name: sidecar
      image: ubuntu:24.04
      command: ["/bin/sh", "-c", "sleep infinity"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
  volumes:
    - name: bpffs
      hostPath:
        path: /sys/fs/bpf
        type: Directory
YAML

microk8s kubectl wait \
  -n bpf-sentinel-demo \
  --for=condition=Ready \
  pod/multi-container-test \
  --timeout=180s
```

Copy the existing helper without installing packages:

```bash
microk8s kubectl exec \
  -n bpf-sentinel-demo simulated-attacker \
  -c attacker -- \
  cat /tmp/bpf-map-test-helper \
  > "$EVIDENCE_DIR/bpf-map-test-helper"

chmod 0755 "$EVIDENCE_DIR/bpf-map-test-helper"

microk8s kubectl exec -i \
  -n bpf-sentinel-demo multi-container-test \
  -c attacker -- \
  sh -c 'cat > /tmp/bpf-map-test-helper && chmod 0755 /tmp/bpf-map-test-helper' \
  < "$EVIDENCE_DIR/bpf-map-test-helper"
```

Generate one protected update:

```bash
microk8s kubectl exec \
  -n bpf-sentinel-demo multi-container-test \
  -c attacker -- \
  /tmp/bpf-map-test-helper \
  /sys/fs/bpf/sentinel-demo/sentinel_test \
  update 9 900
```

Expected fields:

```text
ns=bpf-sentinel-demo
pod=multi-container-test
container=attacker
MAP_NAME=sentinel_test
PROTECTED=yes
```

It must not report `container=sidecar`.

Record the identity:

```bash
microk8s kubectl get pod multi-container-test \
  -n bpf-sentinel-demo \
  -o custom-columns='NAMESPACE:.metadata.namespace,POD:.metadata.name,POD_UID:.metadata.uid,CONTAINERS:.spec.containers[*].name' \
  | tee "$EVIDENCE_DIR/multi-container-identity.txt"
```

## 10. Start a clean repeatability session

Stop Sentinel, repeat Step 3 to recreate the protected map, then run in Terminal A:

```bash
export EVIDENCE_DIR="$HOME/cybr599/evidence/v2.0-final-validation"

sudo env \
  BPF_SENTINEL_KUBECTL="microk8s kubectl" \
  BPF_SENTINEL_PROTECTED_MAP_NAMES="sentinel_test=SentinelTest" \
  python3 -u k8s-aware-BPF-sentinel2.py \
  2>&1 | tee "$EVIDENCE_DIR/sentinel-repeatability.log"
```

## 11. Idle CPU and memory

In Terminal C:

```bash
command -v pidstat >/dev/null || {
  sudo apt update
  sudo apt install -y sysstat
}

export EVIDENCE_DIR="$HOME/cybr599/evidence/v2.0-final-validation"
SENTINEL_PID="$(sudo pgrep -n -f 'python3 .*k8s-aware-BPF-sentinel2.py')"

sudo ps -p "$SENTINEL_PID" \
  -o pid,ppid,%cpu,%mem,rss,vsz,etime,args \
  | tee "$EVIDENCE_DIR/sentinel-process.txt"

sudo pidstat -h -r -u \
  -p "$SENTINEL_PID" 1 60 \
  | tee "$EVIDENCE_DIR/overhead-idle.txt"
```

Generate no test events during these 60 seconds.

## 12. Ten updates and ten deletions

Start load measurement in Terminal C:

```bash
SENTINEL_PID="$(sudo pgrep -n -f 'python3 .*k8s-aware-BPF-sentinel2.py')"

sudo pidstat -h -r -u \
  -p "$SENTINEL_PID" 1 75 \
  > "$EVIDENCE_DIR/overhead-under-load.txt" &

METRICS_PID=$!
```

Immediately run in Terminal B:

```bash
export EVIDENCE_DIR="$HOME/cybr599/evidence/v2.0-final-validation"

for key in $(seq 1 10); do
  microk8s kubectl exec \
    -n bpf-sentinel-demo simulated-attacker \
    -c attacker -- \
    /tmp/bpf-map-test-helper \
    /sys/fs/bpf/sentinel-demo/sentinel_test \
    update "$key" "$((1000 + key))" \
    | tee -a "$EVIDENCE_DIR/helper-repeatability.log"
done

for key in $(seq 1 10); do
  microk8s kubectl exec \
    -n bpf-sentinel-demo simulated-attacker \
    -c attacker -- \
    /tmp/bpf-map-test-helper \
    /sys/fs/bpf/sentinel-demo/sentinel_test \
    delete "$key" \
    | tee -a "$EVIDENCE_DIR/helper-repeatability.log"
done
```

In Terminal C:

```bash
wait "$METRICS_PID"
```

Expected: 10 update alerts, 10 deletion alerts, 20 protected tampering lines, mutation counters at 20, and `lost_events=0`.

## 13. Five freeze and denial cycles

Run in Terminal B:

```bash
export EVIDENCE_DIR="$HOME/cybr599/evidence/v2.0-final-validation"

for cycle in $(seq 1 5); do
  echo "=== Freeze cycle $cycle ===" \
    | tee -a "$EVIDENCE_DIR/helper-freeze-repeatability.log"

  microk8s kubectl exec \
    -n bpf-sentinel-demo simulated-attacker \
    -c attacker -- \
    sh -eu -c '
      p=/sys/fs/bpf/sentinel-demo/sentinel_test
      test ! -e "$p" || unlink "$p"
      bpftool map create "$p" \
        type hash key 4 value 4 entries 64 \
        name sentinel_test
    '

  microk8s kubectl exec \
    -n bpf-sentinel-demo simulated-attacker \
    -c attacker -- \
    /tmp/bpf-map-test-helper \
    /sys/fs/bpf/sentinel-demo/sentinel_test \
    update 1 "$cycle" \
    | tee -a "$EVIDENCE_DIR/helper-freeze-repeatability.log"

  microk8s kubectl exec \
    -n bpf-sentinel-demo simulated-attacker \
    -c attacker -- \
    /tmp/bpf-map-test-helper \
    /sys/fs/bpf/sentinel-demo/sentinel_test \
    freeze \
    | tee -a "$EVIDENCE_DIR/helper-freeze-repeatability.log"

  if microk8s kubectl exec \
    -n bpf-sentinel-demo simulated-attacker \
    -c attacker -- \
    /tmp/bpf-map-test-helper \
    /sys/fs/bpf/sentinel-demo/sentinel_test \
    update 2 999 \
    >> "$EVIDENCE_DIR/helper-freeze-repeatability.log" 2>&1; then
    echo "ERROR: post freeze update unexpectedly succeeded"
    exit 1
  else
    echo "PASS: post freeze update was denied" \
      | tee -a "$EVIDENCE_DIR/helper-freeze-repeatability.log"
  fi
done
```

Expected: five successful pre-freeze updates, five freezes, five failed post-freeze updates returning `Operation not permitted`, counters near 30 successful/protected mutations, and zero lost events.

## 14. Count the recorded evidence

After the last statistics line, stop Sentinel. Run:

```bash
LOG="$EVIDENCE_DIR/sentinel-repeatability.log"

grep -c 'BPF MAP UPDATE:.*RESULT=success.*MAP_NAME=sentinel_test.*PROTECTED=yes' "$LOG"
grep -c 'BPF MAP DELETE:.*RESULT=success.*MAP_NAME=sentinel_test.*PROTECTED=yes' "$LOG"
grep -c 'BPF MAP FREEZE:.*RESULT=success.*MAP_NAME=sentinel_test.*PROTECTED=yes' "$LOG"
grep -c 'BPF MAP UPDATE:.*RESULT=failed' "$LOG"
grep -c 'PROTECTED BPF MAP TAMPERING DETECTED' "$LOG"
grep '^\[STATS\]' "$LOG" | tail -n 1
```

Expected counts, in command order:

| Evidence | Count |
|---|---:|
| Successful updates | 15 |
| Successful deletions | 10 |
| Successful freezes | 5 |
| Failed post-freeze updates | 5 |
| Protected tampering lines | 30 |

## 15. Calculate metadata failure rate

```bash
python3 - "$EVIDENCE_DIR/sentinel-repeatability.log" <<'PY'
import re
import sys

with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
    stats = [line.strip() for line in handle if line.startswith("[STATS]")]

if not stats:
    raise SystemExit("No statistics line found")

line = stats[-1]
values = dict((k, int(v)) for k, v in re.findall(r"(\w+)=(\d+)", line))
events = values.get("kernel_events", 0)
failures = values.get("metadata_failures", 0)
rate = 100.0 * failures / events if events else 0.0

print(line)
print(f"metadata_failure_rate={rate:.2f}% ({failures}/{events})")
PY
```

`metadata_failures` means enrichment failed for some short-lived processes. It is not event loss. Report it separately from `lost_events`.

## 16. Review overhead

```bash
less "$EVIDENCE_DIR/overhead-idle.txt"
less "$EVIDENCE_DIR/overhead-under-load.txt"
```

Report average CPU, resident memory, operation count, workload duration, and lost events. Call this prototype process overhead under the laboratory workload, not total cluster overhead.

## 17. Paper readiness checklist

- Protected update, deletion, freeze, and failed post-freeze update recorded
- PID and TID match helper output
- Map ID and name match `bpftool`
- Protected and unprotected classifications differ
- Exact namespace, pod, and container attributed
- Host and Calico controls pass
- CAP_BPF and enumeration detected
- Correlation demonstrated or its absence documented
- Repeated counts match expectations
- `lost_events=0`
- CPU, memory, and metadata failure rate recorded

## 18. Cleanup after saving evidence

```bash
microk8s kubectl delete pod multi-container-test \
  -n bpf-sentinel-demo \
  --ignore-not-found

if sudo test -e /sys/fs/bpf/sentinel-demo/unprotected_test; then
  sudo unlink /sys/fs/bpf/sentinel-demo/unprotected_test
fi
```

Keep the main namespace until the paper screenshots and demonstration are complete.

## Correct final claim

> BPF Sentinel detects successful and failed BPF map mutation attempts, identifies the responsible process and Kubernetes workload, and distinguishes administrator-designated protected maps from other maps in a controlled Kubernetes laboratory environment.

Version 2.4.2 detects and reports operations. It does not prevent them; prevention belongs to the later BPF LSM version.
