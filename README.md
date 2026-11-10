# ebpf-lab

Hands-on eBPF practice, from bpftrace scripts to C programs built with libbpf.

All folders were tested on WSL2 with Ubuntu 26.04 and Linux kernel 6.18.

## Contents

| Folder | Description |
|---|---|
| `01-bpftrace-oneliners/` | bpftrace scripts for tracing `execve` and timing `do_nanosleep` |
| `02-libbpf-bootstrap/` | The [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) examples, added as a git submodule |
| `03-exec-logger/` | C tool that logs `execve` calls using libbpf and a ring buffer |
| `04-tcp-logger/` | C tool that logs outgoing IPv4 TCP connections |
| `05-xdp-counter/` | XDP packet and byte counter, tested on a veth pair with `setup-net.sh` |

## Clone

```bash
git clone --recurse-submodules https://github.com/greedgarden/ebpf-lab.git
cd ebpf-lab
```

If you already cloned without submodules, run this from the repo root:

```bash
git submodule update --init --recursive
```

## Install the requirements

```bash
sudo apt update
sudo apt install -y bpftrace clang llvm gcc make pkg-config libelf-dev zlib1g-dev libssl-dev bpftool
```

## Run the bpftrace scripts

Loading BPF programs requires root.

```bash
cd 01-bpftrace-oneliners
sudo bpftrace execve.bt
```

Run a command such as `ls -l /tmp` in a second terminal, and press `Ctrl-C` to stop tracing. To try the other script, run `sudo bpftrace sleep-latency.bt` and then `sleep 1` in the second terminal.

## Build and run the libbpf example

Build from the repo root:

```bash
cd 02-libbpf-bootstrap/libbpf-bootstrap/examples/c
make -j"$(nproc)" minimal minimal_ns
```

Run the program in Terminal 1:

```bash
sudo ./minimal_ns
```

Read its output in Terminal 2:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

You should see about one `BPF triggered from PID ...` line per second.

## WSL note

Use `minimal_ns` on WSL, not `minimal`. In the tested WSL setup, the shell runs outside the root PID namespace, so `minimal` compares two different PIDs for the same process and prints nothing.
