#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <net/if.h>
#include <arpa/inet.h>     // inet_pton
#include <bpf/libbpf.h>
#include <linux/netfilter.h>
#include "hook_cmp.h"
#include "hook_cmp.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
	stop = 1;
}

static int read_totals(struct hook_cmp_bpf *skel, struct counters *values,
		       int ncpus, struct counters *totals, __u32 key)
{
	int err, i;

	err = bpf_map__lookup_elem(skel->maps.stats, &key, sizeof(key), values,
				   sizeof(*values) * ncpus, 0);
	if (err)
		return err;

	totals[key].packets = 0;
	totals[key].bytes = 0;
	totals[key].drops = 0;
	for (i = 0; i < ncpus; i++) {
		totals[key].packets += values[i].packets;
		totals[key].bytes += values[i].bytes;
		totals[key].drops += values[i].drops;
	}
	return 0;
}

struct arguments {
	int ifindex;
	const char *dev;
	struct in_addr src;
	const char *src_str;

	int hook_at_num;
	bool hook_at[CMP_HOOK_NUM];

	DROP_RULES drop_rules[CMP_HOOK_NUM];

	bool is_help;
} static g_arg = {
	.dev = "veth0",
	.src_str = "10.200.0.2",
	.hook_at_num = 0,
	.hook_at = { false, false, false, false },
	.is_help = false,
};

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [--dev IFNAME] [--src IPV4] [--hook-at HOOK[,HOOK...]] [--drop PROTO@HOOK]\n", prog);
	fprintf(stderr, "  --dev      the interface name          				default: veth0\n");
	fprintf(stderr, "  --src      the source IP           					default: 10.200.0.2\n");
	fprintf(stderr, "  --hook-at  hooks to attach, separated by commas      default: NULL\n");
	fprintf(stderr, "  --drop     drop rule, e.g., icmp@tc 					default: don't drop\n");
	fprintf(stderr, "             The hook is attached automatically.\n");
	fprintf(stderr, "             PROTO: icmp | tcp | udp\n");
	fprintf(stderr, "             HOOK: the hook to attach to\n");
}

static const char *g_hooks[] = {
	[CMP_HOOK_PREROUTING] = "prerouting",
	[CMP_HOOK_LOCALIN] = "localin",
	[CMP_HOOK_XDP] = "xdp",
	[CMP_HOOK_TC] = "tc",
};

static const int g_display_order[] = {
	CMP_HOOK_XDP,
	CMP_HOOK_TC,
	CMP_HOOK_PREROUTING,
	CMP_HOOK_LOCALIN,
};
static const char *g_display_order_str[] = {
	[CMP_HOOK_XDP] = "XDP",
	[CMP_HOOK_TC] = "TC",
	[CMP_HOOK_PREROUTING] = "PRE_ROUTING",
	[CMP_HOOK_LOCALIN] = "LOCAL_IN",
};

static int parse_arg(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{ "dev",     required_argument, NULL,       'd' },
		{ "src",     required_argument, NULL,       's' },
		{ "hook-at", required_argument, NULL,       'H' },
		{ "drop", required_argument, NULL,       	'D' },
		{ "help",    no_argument,       NULL,       'h' },
		{ 0 }
	};
	int hook_num = sizeof(g_hooks) / sizeof(g_hooks[0]);

	int opt;
	while ((opt = getopt_long(argc, argv, "d:s:H:D:h", long_opts, NULL)) != -1) {
		switch (opt) {
			case 'd':
				g_arg.dev = optarg;
				break;
			case 's':
				g_arg.src_str = optarg;
				break;
			case 'H': {
				g_arg.hook_at_num = 0;
				char *token = strtok(optarg, ",");
				while (token && g_arg.hook_at_num < CMP_HOOK_NUM) {
					int i;
					for (i = 0; i < hook_num; i++) {
						if (strcasecmp(token, g_hooks[i]) == 0) {
							g_arg.hook_at[i] = true;
							g_arg.hook_at_num++;
							break;
						}
					}
					if (i == hook_num) {
						fprintf(stderr, "Invalid hook: %s\n", token);
						return 1;
					}
					token = strtok(NULL, ",");
				}
				break;
			}
			case 'D': {
				char *proto_str = strtok(optarg, "@");
				char *hook_str = strtok(NULL, "@");
				if (!proto_str || !hook_str) {
					fprintf(stderr, "Invalid drop rule format: %s\n", optarg);
					return 1;
				}
				int i = 0;
				for (i = 0; i < hook_num; i++) {
					if (strcasecmp(hook_str, g_hooks[i]) == 0) {
						if (g_arg.drop_rules[i].num >= DROP_PROTO_MAX) {
							fprintf(stderr, "Too many protocols for hook %s, max is %d\n", g_hooks[i], DROP_PROTO_MAX);
							return 1;
						}
						if (strcasecmp(proto_str, "icmp") == 0) {
							g_arg.drop_rules[i].proto[g_arg.drop_rules[i].num] = IPPROTO_ICMP;
						} else if (strcasecmp(proto_str, "tcp") == 0) {
							g_arg.drop_rules[i].proto[g_arg.drop_rules[i].num] = IPPROTO_TCP;
						} else if (strcasecmp(proto_str, "udp") == 0) {
							g_arg.drop_rules[i].proto[g_arg.drop_rules[i].num] = IPPROTO_UDP;
						} else {
							fprintf(stderr, "Invalid protocol: %s\n", proto_str);
							return 1;
						}
						g_arg.drop_rules[i].num++;
						break;
					}
				}
				if (i == hook_num) {
					fprintf(stderr, "Invalid hook: %s\n", hook_str);
					return 1;
				}
				break;
			}
			case 'h':
				g_arg.is_help = true;
				return 0;
			default:
				usage(argv[0]);
				return 1;
		}
	}

	g_arg.ifindex = if_nametoindex(g_arg.dev);
	if (!g_arg.ifindex) {
		fprintf(stderr, "Failed to get ifindex for device %s\n", g_arg.dev);
		return 1;
	}

	if (inet_pton(AF_INET, g_arg.src_str, &g_arg.src) != 1) {
		fprintf(stderr, "invalid IPv4 address: %s\n", g_arg.src_str);
		return 1;
	}

	if (g_arg.hook_at_num == 0) {
		fprintf(stderr, "No hooks specified, attaching to all hooks by default.\n");
		for (int i = 0; i < CMP_HOOK_NUM; i++) {
			g_arg.hook_at[i] = true;
			g_arg.hook_at_num++;
		}
	}

	for (int i = 0; i < CMP_HOOK_NUM; i++) {
		if (!g_arg.hook_at[i] && g_arg.drop_rules[i].num > 0) {
			fprintf(stderr, "Drop rules specified for hook %s, but the hook is not enabled. Enabling the hook.\n", g_hooks[i]);
			g_arg.hook_at[i] = true;
			g_arg.hook_at_num++;
		}
	}

	for (int i = 0; i < CMP_HOOK_NUM; i++) {
		printf("Hook %s: %s\n", g_hooks[i], g_arg.hook_at[i] ? "enabled" : "disabled");
		if (g_arg.drop_rules[i].num > 0) {
			printf("  Drop rules for hook %s: ", g_hooks[i]);
			for (int j = 0; j < g_arg.drop_rules[i].num; j++) {
				printf("%s ", g_arg.drop_rules[i].proto[j] == IPPROTO_ICMP ? "ICMP" :
						g_arg.drop_rules[i].proto[j] == IPPROTO_TCP ? "TCP" :
						g_arg.drop_rules[i].proto[j] == IPPROTO_UDP ? "UDP" : "UNKNOWN");
			}
			printf("\n");
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct hook_cmp_bpf *skel;
	struct counters *values = NULL;
	struct counters totals[CMP_HOOK_NUM] = {};
	int ncpus;
	int err = 0;
	struct bpf_link *links[CMP_HOOK_NUM] = { NULL };
	LIBBPF_OPTS(bpf_netfilter_opts, prerouting_opts, .pf = NFPROTO_IPV4 , .hooknum = NF_INET_PRE_ROUTING, .priority = 200);
	LIBBPF_OPTS(bpf_netfilter_opts, localin_opts, .pf = NFPROTO_IPV4 , .hooknum = NF_INET_LOCAL_IN, .priority = 200);
	LIBBPF_OPTS(bpf_tcx_opts, tc_opts);

	err = parse_arg(argc, argv);
	if (err) {
		return err;
	}

	if (g_arg.is_help) {
		usage(argv[0]);
		return 0;
	}

	ncpus = libbpf_num_possible_cpus();
	if (ncpus < 0) {
		fprintf(stderr, "Failed to get CPU count: %d\n", ncpus);
		return 1;
	}

	values = calloc(ncpus, sizeof(*values));
	if (!values) {
		perror("calloc");
		return 1;
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);


	skel = hook_cmp_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF program\n");
		return 1;
	}

	for (int i = 0; i < CMP_HOOK_NUM; i++) {
		memcpy(&skel->rodata->drop_rules[i], &g_arg.drop_rules[i], sizeof(DROP_RULES));
	}
	skel->rodata->target_saddr = g_arg.src.s_addr;

	err = hook_cmp_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF program: %d\n", err);
		goto cleanup;
	}

	if (g_arg.hook_at[CMP_HOOK_XDP]) {
		links[CMP_HOOK_XDP] = bpf_program__attach_xdp(skel->progs.xdp_prog, g_arg.ifindex);
		if (!links[CMP_HOOK_XDP]) {
			err = -errno;
			fprintf(stderr, "Failed to attach XDP program: %d\n", err);
			goto cleanup;
		}
	}
	if (g_arg.hook_at[CMP_HOOK_TC]) {
		links[CMP_HOOK_TC] = bpf_program__attach_tcx(skel->progs.tc_prog, g_arg.ifindex, &tc_opts);
		if (!links[CMP_HOOK_TC]) {
			err = -errno;
			fprintf(stderr, "Failed to attach TC program: %d\n", err);
			goto cleanup;
		}
	}
	if (g_arg.hook_at[CMP_HOOK_PREROUTING]) {
		links[CMP_HOOK_PREROUTING] = bpf_program__attach_netfilter(skel->progs.nf_prog, &prerouting_opts);
		if (!links[CMP_HOOK_PREROUTING]) {
			err = -errno;
			fprintf(stderr, "Failed to attach netfilter program: %d\n", err);
			goto cleanup;
		}
	}
	if (g_arg.hook_at[CMP_HOOK_LOCALIN]) {
		links[CMP_HOOK_LOCALIN] = bpf_program__attach_netfilter(skel->progs.nf_prog, &localin_opts);
		if (!links[CMP_HOOK_LOCALIN]) {
			err = -errno;
			fprintf(stderr, "Failed to attach LOCAL_IN: %d\n", err);
			goto cleanup;
		}
	}

	printf("Handling packets from Netfilter hooks.\n"
			"Press Ctrl-C to stop.\n");

	while (!stop) {
		sleep(1);

		err = read_totals(skel, values, ncpus, totals, CMP_HOOK_XDP);
		if (err) {
			fprintf(stderr, "Failed to read counters: %d\n", err);
			break;
		}
		err = read_totals(skel, values, ncpus, totals, CMP_HOOK_TC);
		if (err) {
			fprintf(stderr, "Failed to read counters: %d\n", err);
			break;
		}
		err = read_totals(skel, values, ncpus, totals, CMP_HOOK_PREROUTING);
		if (err) {
			fprintf(stderr, "Failed to read counters: %d\n", err);
			break;
		}
		err = read_totals(skel, values, ncpus, totals, CMP_HOOK_LOCALIN);
		if (err) {
			fprintf(stderr, "Failed to read counters: %d\n", err);
			break;
		}

		for (int i = 0; i < sizeof(g_display_order) / sizeof(g_display_order[0]); i++) {
			int hook = g_display_order[i];
			if (i > 0) {
				printf(" | ");
			}
			printf("%s: pkts=%llu bytes=%llu drops=%llu",
				g_display_order_str[hook], totals[hook].packets, totals[hook].bytes, totals[hook].drops);
		}
		printf("\n");
	}

cleanup:
	for (int i = 0; i < CMP_HOOK_NUM; i++) {
		bpf_link__destroy(links[i]);
	}
	hook_cmp_bpf__destroy(skel);
	free(values);
	return err ? 1 : 0;
}
