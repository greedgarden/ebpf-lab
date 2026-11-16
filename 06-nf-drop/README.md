# 06-nf-drop

A BPF program attached to the netfilter PRE_ROUTING and LOCAL_IN hooks. It reads each packet's IPv4 header, counts packets per hook, and drops packets that match a rule.

The goal was to see where in the receive path a packet gets dropped, and what changes when the same rule runs at a different hook.

## How it works

```
veth0 → PRE_ROUTING → routing decision ─┬→ LOCAL_IN → local socket
                                        └→ FORWARD  (not used here)
```

- **One program, two links.** `nf_drop.c` loads one `SEC("netfilter")` program and attaches it twice with `bpf_program__attach_netfilter()`: once at `NF_INET_PRE_ROUTING` and once at `NF_INET_LOCAL_IN`, both with priority 200. The program reads `ctx->state->hook` to know which hook called it.
- **Reading the packet.** The program uses the `bpf_dynptr_from_skb()` and `bpf_dynptr_slice()` kfuncs to read the IP header safely. At IPv4 netfilter hooks, offset 0 is the start of the IP header.
- **Rule.** Packets from `10.200.0.2` are counted per hook. ICMP packets from that address are dropped at LOCAL_IN; everything else is accepted.
- **Counters.** A per-CPU array map holds `packets`, `bytes`, and `drops` for each hook. User space adds up the per-CPU values once per second. Only packets from `10.200.0.2` are counted.

## Requirements

- Linux kernel with `CONFIG_NETFILTER_BPF_LINK=y` and BTF (`/sys/kernel/btf/vmlinux`)
- The packages from the [top-level README](../README.md#install-the-requirements)
- libbpf built from the `02-libbpf-bootstrap` submodule. Build only libbpf with:

  ```bash
  cd ../02-libbpf-bootstrap/libbpf-bootstrap/examples/c
  make "$PWD/.output/libbpf.a"
  ```

  This also installs the libbpf headers such as `bpf_helpers.h` into `.output/bpf/`.

Tested on WSL2 with Ubuntu 26.04 and kernel `6.18.58.1-microsoft-standard-WSL2`, x86_64.

## Build

```bash
make
```

The Makefile generates `vmlinux.h` from the running kernel's BTF the first time you build. The file is ignored by git, because it depends on the kernel you build on.

## Run

Terminal 1: create the test network and start the program.

```bash
sudo ../05-xdp-counter/setup-net.sh up
sudo ./nf_drop
```

`setup-net.sh` creates a `xdp-test` network namespace connected by a veth pair: `10.200.0.2` in the namespace, `10.200.0.1` on the host.

Terminal 2: watch the trace output.

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Terminal 3: send traffic from the namespace to the host.

```bash
sudo ip netns exec xdp-test ping -c 3 10.200.0.1
```

Optionally, check that the program is attached at both hooks:

```bash
sudo bpftool link
```

You should see two `netfilter` links that point to the same program, one at `ip prerouting prio 200` and one at `ip input prio 200`.

When you are done, stop `nf_drop` with `Ctrl-C` and remove the test network:

```bash
sudo ../05-xdp-counter/setup-net.sh down
```

## Results

### Drop at LOCAL_IN (current code)

After `ping -c 3`, ping reports 100% packet loss, and the counters show:

```
PRE_ROUTING: packets=3 bytes=252 drops=0
LOCAL_IN: packets=0 bytes=0 drops=3
```

Each echo request appears twice in `trace_pipe`: accepted at hook 0 (PRE_ROUTING), then dropped at hook 1 (LOCAL_IN).

```
bpf_trace_printk: hook=0 proto=1 src=10.200.0.2 dst=10.200.0.1
bpf_trace_printk: dropping icmp packet from 10.200.0.2 to 10.200.0.1 (hook=1 proto=1)
```

The packet passed PRE_ROUTING and the routing decision, and was dropped only when it reached LOCAL_IN.

### Drop at PRE_ROUTING (earlier version)

An earlier version dropped ICMP at the first hook it reached, which is PRE_ROUTING. That version counted every packet at each hook, before the drop decision. After `ping -c 3`, PRE_ROUTING had counted 3 more packets than LOCAL_IN. The 3 echo requests were dropped at PRE_ROUTING, so the program never ran for them at LOCAL_IN.

To try this again, remove `ctx->state->hook == NF_INET_LOCAL_IN` from the drop condition in `nf_drop.bpf.c`.

### Packets that never reach LOCAL_IN

A packet to an address that is not on this host stops at the routing decision, before LOCAL_IN. To test this, give the namespace a default route through the host and ping an outside address:

```bash
sudo ip netns exec xdp-test ip route add default via 10.200.0.1
nstat -n
sudo ip netns exec xdp-test ping -c 3 8.8.8.8
nstat | grep -iE "InAddrErrors|InNoRoutes|OutDestUnreachs"
```

IP forwarding is off on the host (`/proc/sys/net/ipv4/ip_forward` is `0`). Ping reports 100% packet loss, and three sources agree that the 3 echo requests were dropped between PRE_ROUTING and LOCAL_IN:

- **BPF counters:** `PRE_ROUTING: packets=3 bytes=252 drops=0` and `LOCAL_IN: packets=0 bytes=0 drops=0`. The drop rule at LOCAL_IN never ran, because the packets never got there.
- **trace_pipe:** three lines with `hook=0 proto=1 src=10.200.0.2 dst=8.8.8.8`, and no `hook=1` lines.
- **Kernel counters:** `nstat` shows `IpInAddrErrors 3`. `OutDestUnreachs` did not change, so the host did not send an ICMP error back, and ping shows only timeouts.

`ip route get` shows the routing result for the same packet:

```
$ ip route get 8.8.8.8 from 10.200.0.2 iif veth0
RTNETLINK answers: No route to host
```

### Other traffic is not dropped

With `python3 -m http.server 8000 --bind 10.200.0.1` on the host, `curl` from the namespace returned HTTP 200. Both hooks counted 7 TCP packets (451 bytes) from `10.200.0.2`, and `trace_pipe` showed `proto=6` at hook 0 and hook 1 for each packet.

### `skb->len` starts at the IP header

The 3 ICMP packets counted 252 bytes, which is 84 bytes each. That matches ping's `56(84) bytes`: a 20-byte IP header, an 8-byte ICMP header, and 56 bytes of data. The 14-byte Ethernet header is not included, because at the netfilter IP hooks the packet data starts at the IP header.

## Notes

- **Verdict values.** `NF_DROP` is 0 and `NF_ACCEPT` is 1, as defined in `/usr/include/linux/netfilter.h`. They are macros, so they are not in `vmlinux.h`, and the program defines them itself. If you swap them by mistake, the program drops every IPv4 packet that reaches the hook until you stop it.
- **Priority.** In the kernel source, `bpf_nf_check_pf_and_hooks()` in `net/netfilter/nf_bpf_link.c` rejects a priority equal to `NF_IP_PRI_FIRST` (`INT_MIN`) or `NF_IP_PRI_LAST` (`INT_MAX`) with `-ERANGE` when the link is created.

  Tested with `NF_IP_PRI_FIRST` for the LOCAL_IN link. The program loaded, the PRE_ROUTING link attached, and the LOCAL_IN attach failed:

  ```
  libbpf: prog 'nf_prog': failed to attach to netfilter: -ERANGE
  Failed to attach LOCAL_IN: -34
  ```

  The verifier accepted the program. The kernel rejected only the attach parameters. With `NF_IP_PRI_FIRST + 1`, the attach succeeded and `bpftool link` showed `ip input prio -2147483647`, so only the exact value is rejected. `NF_IP_PRI_LAST` was not tested.
- **kfunc declarations.** The generated `vmlinux.h` does not declare `bpf_dynptr_from_skb()` or `bpf_dynptr_slice()`, so `nf_drop.bpf.c` declares them with `extern ... __ksym`. libbpf resolves them against the kernel BTF when it loads the program.
- **Global variables and the skeleton.** A non-static global variable in the BPF program is exported in the skeleton as `skel->data`. `match_ip` is `static` so that `nf_drop.c` does not need its type.
