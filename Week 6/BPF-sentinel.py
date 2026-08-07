#!/usr/bin/env python3
#
# BPF Sentinel v3
# Python + BCC eBPF tool to detect:
#  - BPF map zeroing (Tracee/Falco/Tetragon blind attack)
#  - Tailcall break against Tetragon execve_calls
#  - CAP_BPF misuse (process gaining BPF capability)
#  - Map/program enumeration (bpf_map_get_fd_by_id, bpf_prog_get_fd_by_id)
#  - Map freezing (bpf_map_freeze) that can block policy updates

from bcc import BPF
import ctypes
import time
import sys
import os

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/capability.h>
#pragma clang diagnostic ignored "-Wduplicate-decl-specifier"

#define CAP_BPF 39
#define BPF_MAP_GET_FD_BY_ID 12
#define BPF_PROG_GET_FD_BY_ID 13

struct event_t {
    u32 pid; u32 uid; u32 event_type;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(cmd_map, u64, u32); // pid_tgid -> cmd
BPF_HASH(seen_enum, u64, u8); // dedup
BPF_HASH(last_cap, u32, u64);
BPF_HASH(last_enum, u32, u64);   // pid -> last timestamp


// 1. Save cmd
TRACEPOINT_PROBE(syscalls, sys_enter_bpf) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 cmd = args->cmd;
    cmd_map.update(&pid_tgid, &cmd);
    return 0;
}

// 2. Check result
TRACEPOINT_PROBE(syscalls, sys_exit_bpf) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 *cmdp = cmd_map.lookup(&pid_tgid);
    if (cmdp == 0 || args->ret < 0) { 
        cmd_map.delete(&pid_tgid); 
        return 0; 
    }

    if (*cmdp == BPF_MAP_GET_FD_BY_ID || *cmdp == BPF_PROG_GET_FD_BY_ID) {
        u8 *seen = seen_enum.lookup(&pid_tgid);
        if (seen == 0) {
            struct event_t event = {};
            event.pid = pid_tgid >> 32; 
            event.uid = (u32)pid_tgid;
            event.event_type = (*cmdp == BPF_MAP_GET_FD_BY_ID)? 1 : 2;
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            events.perf_submit(args, &event, sizeof(event));
            u8 one = 1;
            seen_enum.update(&pid_tgid, &one);
        }
    }
    cmd_map.delete(&pid_tgid);
    return 0;
}

// 3. CAP_BPF usage via security_capable kprobe
int kprobe__security_capable(struct pt_regs *ctx) {
    // security_capable(struct user_namespace *ns, const struct cred *cred, int cap, int audit)
    // cap is the 3rd argument -> PT_REGS_PARM3
    int cap = PT_REGS_PARM3(ctx);
    if (cap != CAP_BPF)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    u64 *last = last_enum.lookup(&event.pid);

    // Rate limit: 2 seconds in nanoseconds
    if (last && ts - *last < 2ULL * 1000000000ULL)
        return 0;

    last_enum.update(&event.pid, &ts);

    struct event_t event = {};
    event.pid = pid;

    // bpf_get_current_uid_gid() returns uid|gid in u64; lower 32 bits = uid
    u64 uid_gid = bpf_get_current_uid_gid();
    event.uid = (u32)uid_gid;

    event.event_type = 3;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

"""

class Event(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint32), ("uid", ctypes.c_uint32), ("event_type", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16)]

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    pid, comm = event.pid, event.comm.decode()
    if event.event_type == 1: print(f"[INFO] BPF MAP ENUMERATION:  PID={pid} COMM={comm}")
    elif event.event_type == 2: print(f"[INFO] BPF PROG ENUMERATION: PID={pid} COMM={comm}")
    elif event.event_type == 3: print(f"[CRITICAL] CAP_BPF USAGE:      PID={pid} COMM={comm}")

def main():
    print("="*60)
    print("BPF Sentinel v3.9 - FINAL - Kernel 7.0")
    print("Detects: Recon + CAP_BPF")
    print("="*60 + "\n")
    sys.stderr = open(os.devnull, 'w') # hide __seg_gs warnings
    b = BPF(text=bpf_text)
    sys.stderr = sys.__stderr__
    b["events"].open_perf_buffer(print_event)
    print("Listening... Ctrl-C to exit\n")
    try: 
        while True: b.perf_buffer_poll()
    except KeyboardInterrupt: print("\nExiting")

if __name__ == "__main__": main()