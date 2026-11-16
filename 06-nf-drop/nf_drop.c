#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>     // inet_pton
#include <bpf/libbpf.h>
#include <linux/netfilter.h>
#include "nf_drop.h"
#include "nf_drop.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
	stop = 1;
}

static int read_totals(struct nf_drop_bpf *skel, struct counters *values,
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
	int drop_hook;
	struct in_addr src;
	const char *src_str;
	bool is_help;
} static g_arg = {
	.drop_hook = NF_INET_LOCAL_IN,
	.src_str = "10.200.0.2",
	.is_help = false,
};

static const char *g_hooks[] = {
	[NF_INET_PRE_ROUTING] = "prerouting",
	[NF_INET_LOCAL_IN] = "localin",
};

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [--src IPV4] [--drop-at prerouting|localin]\n", prog);
}

static int parse_arg(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{ "src",     required_argument, NULL,       's' },
		{ "drop-at", required_argument, NULL,       'd' },
		{ "help",    no_argument,       NULL,       'h' },
		{ 0 }
	};

	int hook_num = sizeof(g_hooks) / sizeof(g_hooks[0]);

	int opt;
	while ((opt = getopt_long(argc, argv, "s:d:h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 's':
			g_arg.src_str = optarg;
			break;
		case 'd': {
			int i;
			for (i = 0; i < hook_num; i++) {
				if (strcasecmp(optarg, g_hooks[i]) == 0) {
					g_arg.drop_hook = i;
					break;
				}
			}
			if (i == hook_num) {
				fprintf(stderr, "invalid hook: %s\n", optarg);
				return 1;
			}
			break;
		}
		case 'h':
			g_arg.is_help = true;
			return 0;
		default:                  /* 不認識的參數：getopt 已經印出錯誤訊息 */
			usage(argv[0]);
			return 1;
		}
	}

	if (inet_pton(AF_INET, g_arg.src_str, &g_arg.src) != 1) {
		fprintf(stderr, "invalid IPv4 address: %s\n", g_arg.src_str);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct nf_drop_bpf *skel;
	struct counters *values = NULL;
	struct counters totals[NF_INET_NUMHOOKS] = {};
	int ncpus;
	int err = 0;
	struct bpf_link *links[NF_INET_NUMHOOKS] = { NULL };
	LIBBPF_OPTS(bpf_netfilter_opts, prerouting_opts, .pf = NFPROTO_IPV4 , .hooknum = NF_INET_PRE_ROUTING, .priority = 200);
	LIBBPF_OPTS(bpf_netfilter_opts, localin_opts, .pf = NFPROTO_IPV4 , .hooknum = NF_INET_LOCAL_IN, .priority = 200);

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


	skel = nf_drop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF program\n");
		return 1;
	}

	skel->rodata->drop_hook = g_arg.drop_hook;
	skel->rodata->target_saddr = g_arg.src.s_addr;

	err = nf_drop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF program: %d\n", err);
		goto cleanup;
	}

	links[NF_INET_PRE_ROUTING] = bpf_program__attach_netfilter(skel->progs.nf_prog, &prerouting_opts);
	if (!links[NF_INET_PRE_ROUTING]) {
		err = -errno;
		fprintf(stderr, "Failed to attach netfilter program: %d\n", err);
		goto cleanup;
	}
	links[NF_INET_LOCAL_IN] = bpf_program__attach_netfilter(skel->progs.nf_prog, &localin_opts);
	if (!links[NF_INET_LOCAL_IN]) {
		err = -errno;
		fprintf(stderr, "Failed to attach LOCAL_IN: %d\n", err);
		goto cleanup;
	}

	printf("Handling packets from Netfilter hooks.\n"
			"Dropping ICMP packets from %s at %s hook.\n"
			"Press Ctrl-C to stop.\n",
			inet_ntoa(g_arg.src), g_hooks[g_arg.drop_hook]);

	while (!stop) {
		sleep(1);

		err = read_totals(skel, values, ncpus, totals, NF_INET_PRE_ROUTING);
		if (err) {
			fprintf(stderr, "Failed to read counters: %d\n", err);
			break;
		}
		err = read_totals(skel, values, ncpus, totals, NF_INET_LOCAL_IN);
		if (err) {
			fprintf(stderr, "Failed to read counters: %d\n", err);
			break;
		}
		printf("PRE_ROUTING: packets=%llu bytes=%llu drops=%llu\n", totals[NF_INET_PRE_ROUTING].packets, totals[NF_INET_PRE_ROUTING].bytes, totals[NF_INET_PRE_ROUTING].drops);
		printf("LOCAL_IN: packets=%llu bytes=%llu drops=%llu\n", totals[NF_INET_LOCAL_IN].packets, totals[NF_INET_LOCAL_IN].bytes, totals[NF_INET_LOCAL_IN].drops);
	}

cleanup:
	bpf_link__destroy(links[NF_INET_LOCAL_IN]);
	bpf_link__destroy(links[NF_INET_PRE_ROUTING]);
	nf_drop_bpf__destroy(skel);
	free(values);
	return err ? 1 : 0;
}
