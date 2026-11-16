#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "hook_cmp.h"

#define NF_DROP 0
#define NF_ACCEPT 1
#define ETH_P_IP	0x0800

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CMP_HOOK_NUM);
	__type(key, __u32);
	__type(value, struct counters);
} stats SEC(".maps");

extern int bpf_dynptr_from_skb(struct __sk_buff *s, __u64 flags,
			       struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *p, __u32 offset,
			      void *buffer__opt, __u32 buffer__szk) __ksym;

const volatile DROP_RULES drop_rules[CMP_HOOK_NUM] = { 0 };
const volatile __u32 target_saddr = 0;

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("tcx/ingress")
int tc_prog(struct __sk_buff *skb)
{
	struct bpf_dynptr ptr;
	struct ethhdr eth_buf;
	struct ethhdr *eth;
	struct iphdr ip_buf;
	struct iphdr *ip;
	struct counters *c;
	__u32 hook_key = CMP_HOOK_TC;
	int i = 0;

	c = bpf_map_lookup_elem(&stats, &hook_key);
	if (!c)
		return TCX_PASS;

	if (bpf_dynptr_from_skb((struct __sk_buff *)skb, 0, &ptr))
		return TCX_PASS;

	eth = bpf_dynptr_slice(&ptr, 0, &eth_buf, sizeof(eth_buf));
	if (!eth)
		return TCX_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TCX_PASS;

	ip = bpf_dynptr_slice(&ptr, sizeof(struct ethhdr), &ip_buf, sizeof(ip_buf));
	if (!ip)
		return TCX_PASS;

	if (ip->version != 4)
		return TCX_PASS;

	if (ip->saddr != target_saddr)
		return TCX_PASS;

	for (i = 0; i < DROP_PROTO_MAX && i < drop_rules[hook_key].num; i++) {
		if (ip->protocol == drop_rules[hook_key].proto[i]) {
			c->drops++;
			bpf_printk("dropping packet from %pI4 to %pI4 (hook=tc, proto=%u)",
				&ip->saddr, &ip->daddr, ip->protocol);
			return TCX_DROP;
		}
	}

	c->packets++;
	c->bytes += skb->len;
	bpf_printk("proto=%u src=%pI4 dst=%pI4 (hook=tc)",
		   ip->protocol, &ip->saddr, &ip->daddr);

	return TCX_PASS;

}

SEC("netfilter")
int nf_prog(struct bpf_nf_ctx *ctx)
{
	struct bpf_dynptr ptr;
	struct iphdr buf;
	struct iphdr *ip;
	struct counters *c;
	__u32 hook_key;
	int i = 0;

	if (ctx->state->hook == NF_INET_PRE_ROUTING)
		hook_key = CMP_HOOK_PREROUTING;
	else if (ctx->state->hook == NF_INET_LOCAL_IN)
		hook_key = CMP_HOOK_LOCALIN;
	else
		return NF_ACCEPT;

	// Skip loopback traffic early: it is always local and only adds noise.
	// lo is always ifindex 1 (LOOPBACK_IFINDEX).
	if (ctx->state->in && ctx->state->in->ifindex == 1)
		return NF_ACCEPT;

	c = bpf_map_lookup_elem(&stats, &hook_key);
	if (!c)
		return NF_ACCEPT;

	/* At IPv4 netfilter hooks, offset 0 is the start of the IP header. */
	if (bpf_dynptr_from_skb((struct __sk_buff *)ctx->skb, 0, &ptr))
		return NF_ACCEPT;

	ip = bpf_dynptr_slice(&ptr, 0, &buf, sizeof(buf));
	if (!ip)
		return NF_ACCEPT;

	if (ip->version != 4)
		return NF_ACCEPT;

	if (ip->saddr != target_saddr)
		return NF_ACCEPT;

	for (i = 0; i < DROP_PROTO_MAX && i < drop_rules[hook_key].num; i++) {
		if (ip->protocol == drop_rules[hook_key].proto[i]) {
			c->drops++;
			bpf_printk("dropping packet from %pI4 to %pI4 (hook=%u, proto=%u)",
				&ip->saddr, &ip->daddr, hook_key, ip->protocol);
			return NF_DROP;
		}
	}

	c->packets++;
	c->bytes += ctx->skb->len;
	bpf_printk("hook=%u proto=%u src=%pI4 dst=%pI4",
		   ctx->state->hook, ip->protocol, &ip->saddr, &ip->daddr);

	return NF_ACCEPT;
}
