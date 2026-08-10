============================================================

BPF Sentinel v2.0 – Clean Edition – Kernel 7.0
Detects: BPF Recon + CAP_BPF Checks + CAP_BPF Set Requests (Deduped)

============================================================

### Features
**Detects BPF Map Enumeration**
- **Detects BPF Program Enumeration**
- **Detects CAP_BPF Privilege Checks**
- **Detects CAP_BPF Set Requests (capset)**
- **Deduplicated Events**
  - One enumeration event per PID
  - One CAP_BPF check per PID per 2 seconds
  - One CAP_BPF set request per PID per 5 seconds

## Requirements

- Python 3
- BCC (BPF Compiler Collection)
- Kernel 5.15+ (tested on Kernel 7.0)
- Root privileges (or CAP_BPF capability)

## How to run
You must have these installed:
`sudo apt install bpfcc-tools python3-bpfcc libcap2-bin bpftool`

save the code in .py, then run it:
`sudo python3 bpf_sentinel.py`

Test the functions with:
`sudo capsh --caps="cap_bpf+eip" -- -c "bpftool prog show > /dev/null"`

