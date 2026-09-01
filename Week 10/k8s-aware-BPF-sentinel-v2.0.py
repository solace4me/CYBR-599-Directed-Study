#!/usr/bin/env python3
"""Kubernetes-aware CAP_BPF, BPF reconnaissance, and map mutation monitor."""

import ctypes
import fnmatch
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time


PROC_ROOT = os.environ.get("BPF_SENTINEL_PROC_ROOT", "/proc")
METADATA_REFRESH_SECONDS = 30
CHAIN_WINDOW_SECONDS = 60
STATS_INTERVAL_SECONDS = 30

EVENT_MAP_ENUM = 1
EVENT_PROG_ENUM = 2
EVENT_CAP_CHECK = 3
EVENT_CAP_SET = 4
EVENT_MAP_UPDATE = 5
EVENT_MAP_DELETE = 6
EVENT_MAP_FREEZE = 7
CONTEXT_RUNC_INIT = 1

BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21
BPF_MAP_FREEZE = 22
BPF_MAP_LOOKUP_AND_DELETE_BATCH = 25
BPF_MAP_UPDATE_BATCH = 26
BPF_MAP_DELETE_BATCH = 27

MAP_MUTATION_EVENTS = {
    EVENT_MAP_UPDATE,
    EVENT_MAP_DELETE,
    EVENT_MAP_FREEZE,
}

BPF_COMMAND_NAMES = {
    BPF_MAP_UPDATE_ELEM: "BPF_MAP_UPDATE_ELEM",
    BPF_MAP_DELETE_ELEM: "BPF_MAP_DELETE_ELEM",
    BPF_MAP_LOOKUP_AND_DELETE_ELEM: "BPF_MAP_LOOKUP_AND_DELETE_ELEM",
    BPF_MAP_FREEZE: "BPF_MAP_FREEZE",
    BPF_MAP_LOOKUP_AND_DELETE_BATCH: "BPF_MAP_LOOKUP_AND_DELETE_BATCH",
    BPF_MAP_UPDATE_BATCH: "BPF_MAP_UPDATE_BATCH",
    BPF_MAP_DELETE_BATCH: "BPF_MAP_DELETE_BATCH",
}

# Trusted Kubernetes system workload filter.
# Match all three fields so an attacker cannot evade reporting by changing only
# a process name or creating a similarly named pod in another namespace.
TRUSTED_CALICO_NAMESPACES = {"kube-system", "calico-system"}
TRUSTED_CALICO_POD_PREFIX = "calico-node-"
TRUSTED_CALICO_CONTAINER = "calico-node"

POD_UID_RE = re.compile(
    r"pod([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_]"
    r"[0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_]"
    r"[0-9a-fA-F]{12})"
)
POD_UID_COMPACT_RE = re.compile(r"pod([0-9a-fA-F]{32})")
RUNTIME_CONTAINER_RE = re.compile(
    r"^(?:cri-containerd|crio|docker)-([0-9a-fA-F]{32,64})(?:\.scope)?$"
)
PLAIN_CONTAINER_RE = re.compile(r"^([0-9a-fA-F]{32,64})(?:\.scope)?$")


def parse_rule_assignments(raw_value, key_parser):
    """Parse comma separated KEY=TOOL protected map rules."""
    rules = {}
    for item in filter(None, (part.strip() for part in raw_value.split(","))):
        key, separator, tool = item.partition("=")
        if not separator or not key.strip() or not tool.strip():
            raise ValueError(f"invalid protected map rule: {item!r}")
        rules[key_parser(key.strip())] = tool.strip()
    return rules


def parse_map_fdinfo(fdinfo_data):
    """Extract BPF map metadata exposed by /proc/PID/fdinfo/FD."""
    parsed = {}
    for line in fdinfo_data.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            parsed[key.strip()] = value.strip()

    result = {}
    if parsed.get("map_id", "").isdigit():
        result["map_id"] = int(parsed["map_id"])
    if parsed.get("map_type", "").isdigit():
        result["map_type_id"] = int(parsed["map_type"])
    if "frozen" in parsed:
        result["frozen"] = parsed["frozen"] not in ("0", "false", "False")
    return result


class MapMetadataResolver:
    """Resolve map identity and match it against administrator supplied rules."""

    def __init__(self):
        self.bpftool = shutil.which("bpftool")
        self.cache = {}
        try:
            self.protected_ids = parse_rule_assignments(
                os.environ.get("BPF_SENTINEL_PROTECTED_MAP_IDS", ""), int
            )
            self.protected_names = parse_rule_assignments(
                os.environ.get("BPF_SENTINEL_PROTECTED_MAP_NAMES", ""), str
            )
        except ValueError as exc:
            raise SystemExit(f"Invalid protected map configuration: {exc}") from exc

    @property
    def protection_configured(self):
        return bool(self.protected_ids or self.protected_names)

    def _read_fdinfo(self, pid, map_fd):
        path = os.path.join(PROC_ROOT, str(pid), "fdinfo", str(map_fd))
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return parse_map_fdinfo(handle.read())
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return {}

    def _query_bpftool(self, map_id, refresh=False):
        if not refresh and map_id in self.cache:
            return dict(self.cache[map_id])
        if not self.bpftool:
            return {}

        try:
            completed = subprocess.run(
                [self.bpftool, "-j", "map", "show", "id", str(map_id)],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            document = json.loads(completed.stdout)
            if isinstance(document, list):
                document = document[0] if document else {}
            if not isinstance(document, dict):
                return {}
            info = {
                "map_name": document.get("name") or "unknown",
                "map_type": document.get("type") or "unknown",
                "frozen": document.get("frozen", "unknown"),
            }
            self.cache[map_id] = dict(info)
            return info
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return {}

    def _protection(self, map_id, map_name):
        if not self.protection_configured:
            return "unconfigured", "unknown"
        if map_id in self.protected_ids:
            return "yes", self.protected_ids[map_id]
        name_resolved = bool(map_name and map_name != "unknown")
        if name_resolved:
            for pattern, tool in self.protected_names.items():
                if fnmatch.fnmatchcase(map_name.lower(), pattern.lower()):
                    return "yes", tool
        id_evaluable = map_id is not None or not self.protected_ids
        name_evaluable = name_resolved or not self.protected_names
        if not (id_evaluable and name_evaluable):
            return "unknown", "unknown"
        return "no", "none"

    def resolve(self, pid, map_fd, refresh=False):
        info = {
            "map_fd": map_fd,
            "map_id": None,
            "map_name": "unknown",
            "map_type": "unknown",
            "frozen": "unknown",
        }
        info.update(self._read_fdinfo(pid, map_fd))
        map_id = info.get("map_id")
        if map_id is not None:
            info.update(self._query_bpftool(map_id, refresh=refresh))
        if info["map_type"] == "unknown" and "map_type_id" in info:
            info["map_type"] = f"id:{info['map_type_id']}"
        protected, tool = self._protection(map_id, info.get("map_name"))
        info["protected"] = protected
        info["security_tool"] = tool
        return info


def normalize_pod_uid(value):
    return value.strip().replace("_", "-").lower()


def parse_k8s_cgroup(cgroup_data):
    """Return real pod UID and container ID from cgroupfs or systemd paths."""
    for line in cgroup_data.splitlines():
        if "kubepods" not in line.lower():
            continue

        path = line.split(":", 2)[-1]
        pod_uid = None
        container_id = None

        pod_match = POD_UID_RE.search(path) or POD_UID_COMPACT_RE.search(path)
        if pod_match:
            pod_uid = normalize_pod_uid(pod_match.group(1))

        for segment in reversed([part for part in path.split("/") if part]):
            match = RUNTIME_CONTAINER_RE.fullmatch(segment)
            if not match:
                match = PLAIN_CONTAINER_RE.fullmatch(segment)
            if match:
                container_id = match.group(1).lower()
                break

        if pod_uid or container_id:
            return {"pod_uid": pod_uid, "container_id": container_id}

    return None


class KubernetesMetadataResolver:
    """Resolve pod/container identifiers with kubectl when it is available."""

    def __init__(self):
        self.command = self._find_kubectl()
        self.pods_by_uid = {}
        self.containers_by_id = {}
        self.last_refresh = 0.0
        self.last_error = None

    @staticmethod
    def _find_kubectl():
        configured = os.environ.get("BPF_SENTINEL_KUBECTL")
        if configured:
            return shlex.split(configured)
        if shutil.which("microk8s"):
            return ["microk8s", "kubectl"]
        if shutil.which("kubectl"):
            return ["kubectl"]
        return None

    def refresh(self, force=False):
        now = time.monotonic()
        if not force and now - self.last_refresh < METADATA_REFRESH_SECONDS:
            return
        self.last_refresh = now

        if not self.command:
            self.last_error = "kubectl not found"
            return

        try:
            completed = subprocess.run(
                self.command + ["get", "pods", "-A", "-o", "json"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            document = json.loads(completed.stdout)
            pods_by_uid = {}
            containers_by_id = {}

            for pod in document.get("items", []):
                metadata = pod.get("metadata", {})
                status = pod.get("status", {})
                uid = normalize_pod_uid(metadata.get("uid", ""))
                pod_info = {
                    "namespace": metadata.get("namespace") or "unknown",
                    "pod": metadata.get("name") or "unknown",
                }
                if uid:
                    pods_by_uid[uid] = pod_info

                status_groups = (
                    status.get("containerStatuses", []),
                    status.get("initContainerStatuses", []),
                    status.get("ephemeralContainerStatuses", []),
                )
                for statuses in status_groups:
                    for container in statuses:
                        raw_id = container.get("containerID") or ""
                        container_id = raw_id.rsplit("://", 1)[-1].lower()
                        if container_id:
                            containers_by_id[container_id] = {
                                **pod_info,
                                "container_name": container.get("name") or "unknown",
                            }

            self.pods_by_uid = pods_by_uid
            self.containers_by_id = containers_by_id
            self.last_error = None
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            self.last_error = str(exc)

    def enrich(self, identifiers):
        self.refresh()
        pod_uid = identifiers.get("pod_uid")
        container_id = identifiers.get("container_id")
        resolved = None

        if container_id:
            resolved = self.containers_by_id.get(container_id)
            if not resolved:
                matches = [
                    info
                    for known_id, info in self.containers_by_id.items()
                    if known_id.startswith(container_id) or container_id.startswith(known_id)
                ]
                if len(matches) == 1:
                    resolved = matches[0]

        if not resolved and pod_uid:
            resolved = self.pods_by_uid.get(normalize_pod_uid(pod_uid))

        return {
            "namespace": (resolved or {}).get("namespace", "unknown"),
            "pod": (resolved or {}).get("pod", "unknown"),
            "pod_uid": pod_uid or "unknown",
            "container_name": (resolved or {}).get("container_name", "unknown"),
            "container_id": container_id or "unknown",
        }


bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/types.h>
#include <linux/capability.h>

#define TASK_COMM_LEN 16
#define CAP_BPF 39
#define BPF_PROG_GET_NEXT_ID 11
#define BPF_MAP_GET_NEXT_ID 12
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_DELETE_ELEM 3
#define BPF_MAP_LOOKUP_AND_DELETE_ELEM 21
#define BPF_MAP_FREEZE 22
#define BPF_MAP_LOOKUP_AND_DELETE_BATCH 25
#define BPF_MAP_UPDATE_BATCH 26
#define BPF_MAP_DELETE_BATCH 27
#define EVENT_MAP_ENUM 1
#define EVENT_PROG_ENUM 2
#define EVENT_CAP_CHECK 3
#define EVENT_CAP_SET 4
#define EVENT_MAP_UPDATE 5
#define EVENT_MAP_DELETE 6
#define EVENT_MAP_FREEZE 7
#define CONTEXT_RUNC_INIT 1
#define CAP_VERSION_1 0x19980330
#define CAP_VERSION_2 0x20071026
#define CAP_VERSION_3 0x20080522

struct event_t {
    u32 pid;
    u32 tid;
    u32 uid;
    u32 event_type;
    u32 bpf_cmd;
    u32 map_fd;
    u32 context_flags;
    u32 reserved;
    s64 result;
    u64 cgroup_id;
    char comm[TASK_COMM_LEN];
};

struct bpf_call_t {
    u32 cmd;
    u32 map_fd;
};

struct bpf_batch_attr_t {
    u64 in_batch;
    u64 out_batch;
    u64 keys;
    u64 values;
    u32 count;
    u32 map_fd;
};

struct cap_header_t {
    u32 version;
    s32 pid;
};

struct cap_data_t {
    u32 effective;
    u32 permitted;
    u32 inheritable;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(bpf_calls, u64, struct bpf_call_t);
BPF_HASH(pending_capset, u64, u8);
BPF_HASH(seen_enum, u64, u8);
BPF_HASH(last_cap_check, u64, u64);
BPF_HASH(last_cap_set, u64, u64);

static __always_inline int submit_event(
    void *ctx, u32 event_type, s64 result, u32 bpf_cmd, u32 map_fd
) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct event_t event = {};
    event.pid = pid_tgid >> 32;
    event.tid = (u32)pid_tgid;
    event.uid = (u32)bpf_get_current_uid_gid();
    event.event_type = event_type;
    event.bpf_cmd = bpf_cmd;
    event.map_fd = map_fd;
    event.result = result;
    event.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    if (event_type == EVENT_CAP_SET &&
        event.comm[0] == 'r' && event.comm[1] == 'u' &&
        event.comm[2] == 'n' && event.comm[3] == 'c' &&
        event.comm[4] == ':' && event.comm[5] == '[' &&
        event.comm[6] == '2' && event.comm[7] == ':' &&
        event.comm[8] == 'I' && event.comm[9] == 'N' &&
        event.comm[10] == 'I' && event.comm[11] == 'T' &&
        event.comm[12] == ']')
        event.context_flags |= CONTEXT_RUNC_INIT;
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_bpf) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct bpf_call_t call = {};
    call.cmd = args->cmd;

    if (call.cmd == BPF_MAP_UPDATE_ELEM ||
        call.cmd == BPF_MAP_DELETE_ELEM ||
        call.cmd == BPF_MAP_LOOKUP_AND_DELETE_ELEM ||
        call.cmd == BPF_MAP_FREEZE) {
        bpf_probe_read_user(&call.map_fd, sizeof(call.map_fd), (void *)args->uattr);
    } else if (call.cmd == BPF_MAP_LOOKUP_AND_DELETE_BATCH ||
               call.cmd == BPF_MAP_UPDATE_BATCH ||
               call.cmd == BPF_MAP_DELETE_BATCH) {
        struct bpf_batch_attr_t batch = {};
        if (bpf_probe_read_user(&batch, sizeof(batch), (void *)args->uattr) == 0)
            call.map_fd = batch.map_fd;
    }

    bpf_calls.update(&pid_tgid, &call);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_bpf) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    struct bpf_call_t *call = bpf_calls.lookup(&pid_tgid);
    if (!call)
        return 0;

    u32 event_type = 0;
    if (call->cmd == BPF_MAP_GET_NEXT_ID)
        event_type = EVENT_MAP_ENUM;
    else if (call->cmd == BPF_PROG_GET_NEXT_ID)
        event_type = EVENT_PROG_ENUM;
    else if (call->cmd == BPF_MAP_UPDATE_ELEM ||
             call->cmd == BPF_MAP_UPDATE_BATCH)
        event_type = EVENT_MAP_UPDATE;
    else if (call->cmd == BPF_MAP_DELETE_ELEM ||
             call->cmd == BPF_MAP_LOOKUP_AND_DELETE_ELEM ||
             call->cmd == BPF_MAP_LOOKUP_AND_DELETE_BATCH ||
             call->cmd == BPF_MAP_DELETE_BATCH)
        event_type = EVENT_MAP_DELETE;
    else if (call->cmd == BPF_MAP_FREEZE)
        event_type = EVENT_MAP_FREEZE;

    if (event_type == EVENT_MAP_ENUM || event_type == EVENT_PROG_ENUM) {
        u64 enum_key = ((u64)pid << 32) | event_type;
        if (!seen_enum.lookup(&enum_key)) {
            submit_event(args, event_type, args->ret, call->cmd, call->map_fd);
            u8 one = 1;
            seen_enum.update(&enum_key, &one);
        }
    } else if (event_type) {
        submit_event(args, event_type, args->ret, call->cmd, call->map_fd);
    }

    bpf_calls.delete(&pid_tgid);
    return 0;
}

TRACEPOINT_PROBE(capability, cap_capable) {
    if (args->cap != CAP_BPF)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 failed = args->ret != 0;
    u64 key = ((u64)pid << 1) | failed;
    u64 now = bpf_ktime_get_ns();
    u64 *last = last_cap_check.lookup(&key);
    if (last && now - *last < 2ULL * 1000000000ULL)
        return 0;
    last_cap_check.update(&key, &now);
    return submit_event(args, EVENT_CAP_CHECK, args->ret, 0, 0);
}

TRACEPOINT_PROBE(syscalls, sys_enter_capset) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct cap_header_t header = {};
    if (bpf_probe_read_user(&header, sizeof(header), (void *)args->header) < 0)
        return 0;

    if (header.version != CAP_VERSION_2 && header.version != CAP_VERSION_3)
        return 0;

    struct cap_data_t upper = {};
    struct cap_data_t *data = (struct cap_data_t *)args->data;
    if (bpf_probe_read_user(&upper, sizeof(upper), &data[1]) < 0)
        return 0;

    u32 cap_bpf_mask = 1U << (CAP_BPF & 31);
    if (!(upper.effective & cap_bpf_mask) &&
        !(upper.permitted & cap_bpf_mask) &&
        !(upper.inheritable & cap_bpf_mask))
        return 0;

    u8 one = 1;
    pending_capset.update(&pid_tgid, &one);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_capset) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u8 *pending = pending_capset.lookup(&pid_tgid);
    if (!pending)
        return 0;
    pending_capset.delete(&pid_tgid);

    u32 pid = pid_tgid >> 32;
    u32 failed = args->ret != 0;
    u64 key = ((u64)pid << 1) | failed;
    u64 now = bpf_ktime_get_ns();
    u64 *last = last_cap_set.lookup(&key);
    if (last && now - *last < 5ULL * 1000000000ULL)
        return 0;
    last_cap_set.update(&key, &now);
    return submit_event(args, EVENT_CAP_SET, args->ret, 0, 0);
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    bpf_calls.delete(&pid_tgid);
    pending_capset.delete(&pid_tgid);

    if (pid == tid) {
        u64 key = ((u64)pid << 32) | EVENT_MAP_ENUM;
        seen_enum.delete(&key);
        key = ((u64)pid << 32) | EVENT_PROG_ENUM;
        seen_enum.delete(&key);

        key = ((u64)pid << 1);
        last_cap_check.delete(&key);
        last_cap_set.delete(&key);
        key |= 1;
        last_cap_check.delete(&key);
        last_cap_set.delete(&key);
    }
    return 0;
}
"""


class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint32),
        ("bpf_cmd", ctypes.c_uint32),
        ("map_fd", ctypes.c_uint32),
        ("context_flags", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("result", ctypes.c_int64),
        ("cgroup_id", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
    ]


class Sentinel:
    def __init__(self):
        self.resolver = KubernetesMetadataResolver()
        self.map_resolver = MapMetadataResolver()
        self.cgroup_cache = {}
        self.chain_state = {}
        self.stats = {
            "kernel_events": 0,
            "k8s_reported": 0,
            "runtime_setup_events": 0,
            "trusted_filtered": 0,
            "host_filtered": 0,
            "metadata_failures": 0,
            "lost_events": 0,
            "correlated_sequences": 0,
            "successful_map_mutations": 0,
            "protected_map_mutations": 0,
        }
        self.last_stats = time.monotonic()

    def lookup_k8s_info(self, pid, cgroup_id):
        cached = self.cgroup_cache.get(cgroup_id) if cgroup_id else None
        if cached:
            return self.resolver.enrich(cached), "k8s"

        try:
            cgroup_path = os.path.join(PROC_ROOT, str(pid), "cgroup")
            with open(cgroup_path, "r", encoding="utf-8", errors="replace") as handle:
                identifiers = parse_k8s_cgroup(handle.read())
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return None, "error"

        if not identifiers:
            return None, "host"

        if cgroup_id:
            self.cgroup_cache[cgroup_id] = identifiers
        return self.resolver.enrich(identifiers), "k8s"

    def correlate(self, event, info):
        now = time.monotonic()
        key = event.cgroup_id or info["container_id"]
        state = self.chain_state.setdefault(key, {})

        for stage in list(state):
            if now - state[stage] > CHAIN_WINDOW_SECONDS:
                del state[stage]

        if event.event_type == EVENT_CAP_SET and event.result == 0:
            state.clear()
            state["cap_set"] = now
        elif event.event_type == EVENT_CAP_CHECK and event.result == 0:
            if "cap_set" in state:
                state["cap_check"] = now
        elif event.event_type in (EVENT_MAP_ENUM, EVENT_PROG_ENUM):
            if event.result >= 0 and "cap_set" in state and "cap_check" in state:
                state.clear()
                self.stats["correlated_sequences"] += 1
                return "reconnaissance"
        elif event.event_type in MAP_MUTATION_EVENTS and event.result == 0:
            if "cap_set" in state and "cap_check" in state:
                state.clear()
                self.stats["correlated_sequences"] += 1
                return "map_mutation"
        return None

    @staticmethod
    def event_status(event):
        if event.event_type in (EVENT_MAP_ENUM, EVENT_PROG_ENUM):
            return "success" if event.result >= 0 else f"failed({event.result})"
        if event.event_type == EVENT_CAP_CHECK:
            return "granted" if event.result == 0 else f"denied({event.result})"
        return "success" if event.result == 0 else f"failed({event.result})"

    @staticmethod
    def is_trusted_system_workload(info):
        """Return True only for the resolved Calico node system container."""
        return (
            info.get("namespace") in TRUSTED_CALICO_NAMESPACES
            and info.get("pod", "").startswith(TRUSTED_CALICO_POD_PREFIX)
            and info.get("container_name") == TRUSTED_CALICO_CONTAINER
        )

    def print_event(self, cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        self.stats["kernel_events"] += 1

        info, origin = self.lookup_k8s_info(event.pid, event.cgroup_id)
        if origin == "host":
            self.stats["host_filtered"] += 1
            self.maybe_print_stats()
            return
        if origin == "error":
            self.stats["metadata_failures"] += 1
            self.maybe_print_stats()
            return

        if self.is_trusted_system_workload(info):
            self.stats["trusted_filtered"] += 1
            self.maybe_print_stats()
            return

        comm = event.comm.decode(errors="replace").rstrip(chr(0))
        runtime_setup = bool(event.context_flags & CONTEXT_RUNC_INIT)
        self.stats["k8s_reported"] += 1
        if runtime_setup:
            self.stats["runtime_setup_events"] += 1
        correlated = self.correlate(event, info)
        labels = {
            EVENT_MAP_ENUM: "BPF MAP ENUMERATION",
            EVENT_PROG_ENUM: "BPF PROG ENUMERATION",
            EVENT_CAP_CHECK: "CAP_BPF CHECK",
            EVENT_CAP_SET: "CAP_BPF SET",
            EVENT_MAP_UPDATE: "BPF MAP UPDATE",
            EVENT_MAP_DELETE: "BPF MAP DELETE",
            EVENT_MAP_FREEZE: "BPF MAP FREEZE",
        }

        map_info = None
        if event.event_type in MAP_MUTATION_EVENTS:
            map_info = self.map_resolver.resolve(
                event.pid,
                event.map_fd,
                refresh=event.event_type == EVENT_MAP_FREEZE and event.result == 0,
            )
            if event.result == 0:
                self.stats["successful_map_mutations"] += 1
                if map_info["protected"] == "yes":
                    self.stats["protected_map_mutations"] += 1

        if runtime_setup:
            level = "INFO"
        elif event.event_type in MAP_MUTATION_EVENTS and event.result == 0:
            level = "CRITICAL"
        elif correlated:
            level = "CRITICAL"
        elif event.event_type in (
            EVENT_CAP_CHECK,
            EVENT_CAP_SET,
            EVENT_MAP_UPDATE,
            EVENT_MAP_DELETE,
            EVENT_MAP_FREEZE,
        ):
            level = "WARNING"
        else:
            level = "INFO"

        container_short = info["container_id"][:12]
        status = self.event_status(event)
        event_line = (
            f"[{level}]"
            f"[ns={info['namespace']}]"
            f"[pod={info['pod']}]"
            f"[pod_uid={info['pod_uid']}]"
            f"[container={info['container_name']}]"
            f"[container_id={container_short}] "
            f"{labels.get(event.event_type, 'UNKNOWN EVENT')}: "
            f"PID={event.pid} TID={event.tid} UID={event.uid} "
            f"COMM={comm} RESULT={status}"
        )
        if map_info is not None:
            map_id = map_info["map_id"]
            event_line += (
                f" OP={BPF_COMMAND_NAMES.get(event.bpf_cmd, event.bpf_cmd)}"
                f" MAP_FD={event.map_fd}"
                f" MAP_ID={map_id if map_id is not None else 'unknown'}"
                f" MAP_NAME={map_info['map_name']}"
                f" MAP_TYPE={map_info['map_type']}"
                f" PROTECTED={map_info['protected']}"
                f" SECURITY_TOOL={map_info['security_tool']}"
            )
        if runtime_setup:
            event_line += " CONTEXT=container_runtime_setup"
        print(event_line)

        if map_info is not None and event.result == 0 and map_info["protected"] == "yes":
            print(
                "[CRITICAL] PROTECTED BPF MAP TAMPERING DETECTED: "
                f"tool={map_info['security_tool']} map_id={map_info['map_id']} "
                f"map_name={map_info['map_name']} pid={event.pid} tid={event.tid}"
            )

        if correlated == "reconnaissance":
            print(
                "[CRITICAL] SUSPICIOUS CAP_BPF SEQUENCE: "
                "successful CAP_BPF set -> granted CAP_BPF check -> successful BPF enumeration"
            )
        elif correlated == "map_mutation":
            print(
                "[CRITICAL] CONFIRMED CAP_BPF MAP MUTATION SEQUENCE: "
                "successful CAP_BPF set -> granted CAP_BPF check -> successful map operation"
            )
        self.maybe_print_stats()

    def lost_event(self, cpu, lost_count):
        self.stats["lost_events"] += lost_count
        print(f"[WARNING] Lost {lost_count} perf events on CPU {cpu}", file=sys.stderr)

    def maybe_print_stats(self, force=False):
        now = time.monotonic()
        if not force and now - self.last_stats < STATS_INTERVAL_SECONDS:
            return
        self.last_stats = now
        print(
            "[STATS] "
            + " ".join(f"{name}={value}" for name, value in self.stats.items())
        )


def run_parser_self_test():
    assert ctypes.sizeof(Event) == 64, "kernel and user event layouts must remain aligned"
    runtime_event = Event()
    runtime_event.context_flags = CONTEXT_RUNC_INIT
    assert runtime_event.context_flags & CONTEXT_RUNC_INIT

    samples = {
        "cgroupfs": (
            "0::/kubepods/burstable/"
            "pod12345678-1234-1234-1234-123456789abc/"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ),
        "systemd-containerd": (
            "0::/kubepods.slice/kubepods-burstable.slice/"
            "kubepods-burstable-pod12345678_1234_1234_1234_123456789abc.slice/"
            "cri-containerd-0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef.scope"
        ),
        "systemd-crio": (
            "0::/kubepods.slice/kubepods-besteffort.slice/"
            "kubepods-besteffort-pod12345678_1234_1234_1234_123456789abc.slice/"
            "crio-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope"
        ),
        "systemd-docker": (
            "0::/kubepods.slice/kubepods-pod12345678_1234_1234_1234_123456789abc.slice/"
            "docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope"
        ),
    }

    for name, sample in samples.items():
        parsed = parse_k8s_cgroup(sample)
        assert parsed is not None, f"{name}: Kubernetes path was not detected"
        assert parsed["pod_uid"] == "12345678-1234-1234-1234-123456789abc"
        assert parsed["container_id"].startswith("0123456789abcdef")

    assert parse_k8s_cgroup("0::/user.slice/user-1000.slice/session-1.scope") is None

    trusted_calico = {
        "namespace": "kube-system",
        "pod": "calico-node-9wh8c",
        "container_name": "calico-node",
    }
    assert Sentinel.is_trusted_system_workload(trusted_calico)
    assert not Sentinel.is_trusted_system_workload(
        {**trusted_calico, "namespace": "default"}
    )
    assert not Sentinel.is_trusted_system_workload(
        {**trusted_calico, "pod": "calico-typha-12345"}
    )
    assert not Sentinel.is_trusted_system_workload(
        {**trusted_calico, "container_name": "sidecar"}
    )

    fdinfo = parse_map_fdinfo(
        "pos:\t0\nflags:\t02000002\nmap_type:\t1\nmap_id:\t42\nfrozen:\t1\n"
    )
    assert fdinfo == {"map_id": 42, "map_type_id": 1, "frozen": True}

    assert parse_rule_assignments("42=Falco,77=Tetragon", int) == {
        42: "Falco",
        77: "Tetragon",
    }
    assert parse_rule_assignments("falco_*=Falco", str) == {"falco_*": "Falco"}

    print(
        "Self-test passed: cgroupfs, containerd, CRI-O, Docker, host filtering, "
        "trusted Calico filtering, event layout, runtime context, map fdinfo parsing, "
        "and protected map rules"
    )


def main():
    if "--self-test" in sys.argv:
        run_parser_self_test()
        return

    try:
        from bcc import BPF
    except ImportError as exc:
        raise SystemExit("BCC Python bindings are required: install python3-bpfcc") from exc

    sentinel = Sentinel()
    print("=" * 88)
    print("BPF Sentinel v2.0 - Kubernetes-aware Map Integrity Edition")
    print(
        "Reports CAP_BPF, BPF enumeration, and direct BPF map mutation events "
        "attributable to Kubernetes cgroups"
    )
    print(
        "Trusted filter: kube-system/calico-node-*/calico-node "
        "(counted as trusted_filtered)"
    )
    print(f"Process metadata source: {PROC_ROOT}/PID/cgroup")
    if sentinel.map_resolver.protection_configured:
        print("Protected map classification: configured")
    else:
        print(
            "Protected map classification: unconfigured "
            "(set BPF_SENTINEL_PROTECTED_MAP_IDS or BPF_SENTINEL_PROTECTED_MAP_NAMES)"
        )
    print("=" * 88)

    sentinel.resolver.refresh(force=True)
    if sentinel.resolver.last_error:
        print(
            "[NOTICE] Kubernetes API metadata unavailable; "
            "pod UID and container ID filtering will still work."
        )

    bpf = BPF(text=bpf_text)
    bpf["events"].open_perf_buffer(
        sentinel.print_event,
        lost_cb=sentinel.lost_event,
        page_cnt=64,
    )
    print("Listening... Ctrl-C to exit\n")

    try:
        while True:
            bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nExiting")
    finally:
        sentinel.maybe_print_stats(force=True)


if __name__ == "__main__":
    main()
