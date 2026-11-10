#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "xdp_counter.h"

#define AF_INET 2

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct counters);
} stats SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx)
{
	__u32 key = 0;
	struct counters *c;

	c = bpf_map_lookup_elem(&stats, &key);
	if (!c)
		return XDP_PASS;

	c->packets++;
	c->bytes += ctx->data_end - ctx->data;

	return XDP_PASS;
}
