#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "nf_drop.h"

#define NF_DROP 0
#define NF_ACCEPT 1

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NF_INET_NUMHOOKS);
	__type(key, __u32);
	__type(value, struct counters);
} stats SEC(".maps");

extern int bpf_dynptr_from_skb(struct __sk_buff *s, __u64 flags,
			       struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *p, __u32 offset,
			      void *buffer__opt, __u32 buffer__szk) __ksym;

const volatile __u32 drop_hook = 0;
const volatile __u32 target_saddr = 0;

SEC("netfilter")
int nf_prog(struct bpf_nf_ctx *ctx)
{
	struct bpf_dynptr ptr;
	struct iphdr buf;
	struct iphdr *ip;
	struct counters *c;
	__u32 key;

	// Skip loopback traffic early: it is always local and only adds noise.
	// lo is always ifindex 1 (LOOPBACK_IFINDEX).
	if (ctx->state->in && ctx->state->in->ifindex == 1)
		return NF_ACCEPT;

	if (ctx->state->hook >= NF_INET_NUMHOOKS)
		return NF_ACCEPT;

	key = ctx->state->hook;
	c = bpf_map_lookup_elem(&stats, &key);
	if (!c)
		return NF_ACCEPT;

	/* At IPv4 netfilter hooks, offset 0 is the start of the IP header. */
	if (bpf_dynptr_from_skb((struct __sk_buff *)ctx->skb, 0, &ptr))
		return NF_ACCEPT;

	ip = bpf_dynptr_slice(&ptr, 0, &buf, sizeof(buf));
	if (!ip)
		return NF_ACCEPT;	/* shorter than an IP header */

	if (ip->version != 4)
		return NF_ACCEPT;

	if (ip->saddr != target_saddr)
		return NF_ACCEPT;

	// drop icmp packets
	if (ip->protocol == IPPROTO_ICMP && ctx->state->hook == drop_hook) {
		c->drops++;
		bpf_printk("dropping icmp packet from %pI4 to %pI4 (hook=%u proto=%u)",
			&ip->saddr, &ip->daddr, ctx->state->hook, ip->protocol);
		return NF_DROP;
	}

	c->packets++;
	c->bytes += ctx->skb->len;
	bpf_printk("hook=%u proto=%u src=%pI4 dst=%pI4",
		   ctx->state->hook, ip->protocol, &ip->saddr, &ip->daddr);

	return NF_ACCEPT;
}
