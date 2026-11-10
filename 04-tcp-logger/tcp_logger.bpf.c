#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "tcp_logger.h"

#define AF_INET 2

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

const volatile __u64 pidns_dev = 0;
const volatile __u64 pidns_ino = 0;

SEC("tp/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct bpf_pidns_info ns;
	struct event *e;

    if (ctx->protocol != IPPROTO_TCP || ctx->family != AF_INET)
		return 0;
	if (ctx->newstate != TCP_SYN_SENT)
		return 0;

	if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns)))
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = ns.tgid;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	__builtin_memcpy(e->saddr, ctx->saddr, sizeof(e->saddr));
	__builtin_memcpy(e->daddr, ctx->daddr, sizeof(e->daddr));
	e->dport = ctx->dport;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
