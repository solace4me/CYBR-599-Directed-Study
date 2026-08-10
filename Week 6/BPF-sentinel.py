#!/usr/bin/env python3
#
# BPF Sentinel v2.0 – Clean Edition – Kernel 7.0
# Features:
# - Deduplicated BPF MAP/PROG enumeration (1 line per process run)
# - Deduplicated CAP_BPF checks (1 line per PID per 2s)
# - Deduplicated CAP_BPF set requests (1 line per PID per 5s)
# - Uses tracepoints only (stable, safe)
# - Clean security-event output

from bcc import BPF
import ctypes
import sys
import os


# eBPF PROGRAM (runs in kernel)
bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/types.h>
#include <linux/capability.h>

#define TASK_COMM_LEN 16
#define CAP_BPF 39
#define BPF_PROG_GET_NEXT_ID 11
#define BPF_MAP_GET_NEXT_ID 12

// Event structure sent to user space
struct event_t {
    u32 pid;
    u32 uid;
    u32 event_type; 
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

// Deduplication maps
BPF_HASH(last_cap_check, u32, u64);   // last CAP_BPF check timestamp per PID
BPF_HASH(last_cap_set, u32, u64);     // last CAP_BPF set request timestamp per PID
BPF_HASH(cmd_map, u64, u32);          // stores bpf() command per thread
BPF_HASH(seen_enum, u32, u8);         // ensures only one enumeration event per PID


// TRACEPOINT: sys_enter_bpf
// Captures the BPF command before execution

TRACEPOINT_PROBE(syscalls, sys_enter_bpf) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 cmd = args->cmd;
    cmd_map.update(&pid_tgid, &cmd);
    return 0;
}


// TRACEPOINT: sys_exit_bpf
// Detects BPF map/program enumeration (recon activity)

TRACEPOINT_PROBE(syscalls, sys_exit_bpf) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 *cmdp = cmd_map.lookup(&pid_tgid);
    if (!cmdp) return 0;

    // Detect enumeration syscalls
    if (*cmdp == BPF_MAP_GET_NEXT_ID || *cmdp == BPF_PROG_GET_NEXT_ID) {

        // Dedup: only one enumeration event per PID
        if (seen_enum.lookup(&pid)) { 
            cmd_map.delete(&pid_tgid); 
            return 0; 
        }

        // Build event
        struct event_t event = {};
        event.pid = pid;
        event.uid = (u32)bpf_get_current_uid_gid();
        event.event_type = (*cmdp == BPF_MAP_GET_NEXT_ID) ? 1 : 2;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        events.perf_submit(args, &event, sizeof(event));

        // Mark PID as seen
        u8 one = 1;
        seen_enum.update(&pid, &one);
    }

    cmd_map.delete(&pid_tgid);
    return 0;
}


// TRACEPOINT: sched_process_exit
// Cleans up dedup maps when a process exits

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    cmd_map.delete(&pid_tgid);

    // Only clear dedup state when the main thread exits
    if (pid == tid) {
        seen_enum.delete(&pid);
        last_cap_check.delete(&pid);
        last_cap_set.delete(&pid);
    }
    return 0;
}


// TRACEPOINT: capability:cap_capable
// Detects CAP_BPF privilege checks (early sign of eBPF misuse)

TRACEPOINT_PROBE(capability, cap_capable) {
    if (args->cap != CAP_BPF) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Filter noisy system daemons
    char comm[TASK_COMM_LEN]; 
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == '(') return 0;

    // Dedup: 2-second window
    u64 ts = bpf_ktime_get_ns();
    u64 *last = last_cap_check.lookup(&pid);
    if (last && ts - *last < 2ULL * 1000000000ULL) return 0;
    last_cap_check.update(&pid, &ts);

    // Build event
    struct event_t event = {};
    event.pid = pid;
    event.uid = (u32)bpf_get_current_uid_gid();
    event.event_type = 3;
    __builtin_memcpy(event.comm, comm, TASK_COMM_LEN);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


// TRACEPOINT: sys_enter_capset
// Detects CAP_BPF being added to a process (privilege escalation)

struct cap_data_t {
    u32 effective;
    u32 permitted;
    u32 inheritable;
};

TRACEPOINT_PROBE(syscalls, sys_enter_capset) {
    struct cap_data_t upper = {};
    struct cap_data_t *data = (struct cap_data_t *)args->data;

    // Read second capability struct (upper set)
    bpf_probe_read_user(&upper, sizeof(upper), &data[1]);

    // CAP_BPF lives in the upper 32-bit mask
    u32 cap_bpf_mask = 1U << (CAP_BPF - 32);

    // If CAP_BPF is not being added, ignore
    if (!(upper.effective & cap_bpf_mask) &&
        !(upper.permitted & cap_bpf_mask) &&
        !(upper.inheritable & cap_bpf_mask))
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Filter noisy system daemons
    char comm[TASK_COMM_LEN]; 
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == '(') return 0;

    // Dedup: 5-second window
    u64 ts = bpf_ktime_get_ns();
    u64 *last = last_cap_set.lookup(&pid);
    if (last && ts - *last < 5ULL * 1000000000ULL) return 0;
    last_cap_set.update(&pid, &ts);

    // Build event
    struct event_t event = {};
    event.pid = pid;
    event.uid = (u32)bpf_get_current_uid_gid();
    event.event_type = 4;
    __builtin_memcpy(event.comm, comm, TASK_COMM_LEN);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""


# USERSPACE EVENT STRUCT
class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16)
    ]


# PRINT EVENT HANDLER
def print_event(cpu, data, size):
    e = ctypes.cast(data, ctypes.POINTER(Event)).contents
    labels = {
        1: "BPF MAP ENUMERATION",
        2: "BPF PROG ENUMERATION",
        3: "CAP_BPF CHECK",
        4: "CAP_BPF SET REQUEST"
    }
    level = "INFO" if e.event_type < 3 else "CRITICAL"
    comm = e.comm.decode(errors="replace").rstrip(chr(0))
    print(f"[{level}] {labels[e.event_type]}: PID={e.pid} UID={e.uid} COMM={comm}")


# MAIN PROGRAM
def main():
    print("=" * 60)
    print("BPF Sentinel v2.0 – Clean Edition – Kernel 7.0")
    print("Detects: BPF Recon + CAP_BPF Checks + CAP_BPF Set Requests (Deduped)")
    print("=" * 60 + "\n")

    # Suppress BCC warnings
    devnull = open(os.devnull, "w")
    old_stderr = sys.stderr
    try:
        sys.stderr = devnull
        b = BPF(text=bpf_text)
    finally:
        sys.stderr = old_stderr
        devnull.close()

    # Open perf buffer
    b["events"].open_perf_buffer(print_event)
    print("Listening... Ctrl-C to exit\n")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nExiting")

if __name__ == "__main__":
    main()
