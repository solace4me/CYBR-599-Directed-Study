## Week 6
## eBPF Architecture
**eBPF Core** 

The eBPF core is the small execution engine that allows sandboxed programs to run safely inside the Linux kernel. It provides the fundamental infrastructure for loading, verifying, attaching, and executing eBPF bytecode. It ensures that programs can observe or react to kernel events without requiring kernel modules making the eBPF both powerful and safe for production systems.

**Verifier**

The verifier is the safety gatekeeper of eBPF. Before any program is allowed to run in the kernel the verifier performs a strict static analysis of the bytecode to ensure memory safety, bounded loops, valid pointer usage, and guaranteed termination. It also prevents programs from crashing the kernel or accessing unauthorized memory. If the verifier cannot prove the safety the program is rejected.

**JIT (Just In Time Compiler)**

The JIT compiler translates eBPF bytecode into native machine instructions for the host CPU. This improves the performance by allowing eBPF programs to run closely to a native speed. The JIT is optional but widely enabled in modern kernels because it reduces overhead for high frequency events such as networking, tracing, and security monitoring.

**Maps**

Maps are shared data structures used by eBPF programs to store and exchange information. They act as communication channels between kernel space and user space. Common map types include hash maps, arrays, LRU caches, ring buffers, and perf event buffers. Maps allow eBPF programs to maintain state, aggregate metrics, store configuration, or emit events to user space tools.

**Hook Points**

Hook points are the locations in the kernel where eBPF programs can attach to. They define when and why an eBPF program runs. Major hook categories include kprobes/uprobes, tracepoints, perf events, cgroup hooks, network TC/XDP hooks, LSM hooks, and system call entry/exit points. Hook points give eBPF deep visibility and control across the entire kernel.

**Production**

In production environments, eBPF is used for high performance observability, security enforcement, networking, and runtime policy systems. eBPF Tools like Cilium, Falco, Tetragon, Katran, and bpftrace rely on eBPF to provide low overhead monitoring and enforcement without kernel patches. Production deployments emphasize safety through  the verifier, stability with tracepoints, and performance by the JIT, making eBPF a modern foundation that is suitable for cloud native and critical security systems.
### Reviewing current works and literature
In order to have better understanding of the recent discoveries and present state of eBPF development, two resources were explored. 

### 1. Securing Kubernetes: An Integrated Approach to AI Driven Threat Detection and eBPF Based Security Monitoring” (WJAETS 2025)

**Main Contribution**

This paper proposes a combined AI + eBPF security architecture for Kubernetes environments. It points out that traditional security tools cannot keep up with the dynamic short nature of containers and that Kubernetes requires a very deep kernel level visibility with Ai driven anomaly detection that can detect modern threats such as cryptojacking, privilege escalation, and unauthorized API access.

**Observations from the write up**

•	Kubernetes has unique security challenges: multi tenancy, ephemeral workloads, complex RBAC, pod to pod communication, and hybrid/multi cluster deployments.

•	Traditional perimeter based security fails because it cannot observe container internals or dynamic cluster behavior.

•	eBPF provides kernel level visibility into process execution, syscalls, network activity, file access, and container lifecycle events.

•	Combined AI + eBPF architecture enables real time detection, automated policy enforcement, and Zero Trust alignment.

•	Performance overhead is minimal, because eBPF executes inside the kernel without context switches.

•	Case studies show eBPF detects container escapes, unauthorized network connections, and sensitive file access with low overhead.

### 2. “Your eBPF Security Monitor Is Running. It’s Also Blind.” (Medium, Azizcan Dastan, 2026)

**Main Contribution**

This article reveals a serious architectural weakness in modern eBPF security tools (Falco, Tracee, Tetragon) their BPF maps can be silently modified, allowing an attacker with CAP_BPF to disable monitoring completely without any logs, errors, or alerts.

**Observation from the article**

•	All major eBPF security tools rely on writable BPF maps for configuration and state.

•	Linux does not enforce ownership or access control on BPF maps which means any CAP_BPF process can modify them.

•	An attacker who escapes a container and gains CAP_BPF can instantly disable monitoring:

    o	Tracee: zeroing enabled_policies disables all detections.
    o	Tetragon: deleting entries in execve_calls breaks the tail call pipeline.
    o	Falco: zeroing interesting_syscalls makes all probes return immediately.
•	No logs, no alerts, no health check failures, tools appear to be running normally.

This paper exposes a blind spot in eBPF security monitoring, which happens not to be a bug but an architectural defect.

**Overall observation**

In general these papers highlight two major gaps in current eBPF security systems:

**Gap 1:** Kubernetes needs deeper kernel visibility with intelligent analysis (WJAETS 2025) states that even an advanced AI driven systems depend on accurate kernel telemetry.

**Gap 2:** eBPF telemetry itself can be tampered with
(Dastan 2026). If an attacker disables the eBPF maps, AI driven detection becomes blind.

Based on these findings, this work will address this gap by creating a tool that detects tampering attempts against BPF maps and capability misuse (CAP_BPF).



### Reference:
-	Literature Review
1.	"Your eBPF Security Monitor Is Running. It’s Also Blind." - Medium, Azizcan Dastan May 2026
2.	Securing kubernetes: An integrated approach to ai-driven threat detection and EBPF-based security monitoring" - WJAETS 2025
3. [Breaking eBPF Security: How Kernel Rootkits Blind Observabil](https://iq.thc.org/breaking-ebpf-security-how-kernel-rootkits-blind-observability-tools)
- Video Resources 
1. Falco vs Tetragon: Which eBPF Runtime Security Tool Should You Choose?" - Devops & AI Hub Jul 2026
2. eBPF Explained: The Complete Deep Dive — BPF VM, Verifier, JIT, Maps, XDP, Cilium & Prod Systems