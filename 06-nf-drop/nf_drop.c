#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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
	for (i = 0; i < ncpus; i++) {
		totals[key].packets += values[i].packets;
		totals[key].bytes += values[i].bytes;
	}
	return 0;
}


int main(void)
{
	struct nf_drop_bpf *skel;
	struct counters *values = NULL;
	struct counters totals[NF_INET_NUMHOOKS];
	int ncpus;
	int err = 0;
	struct bpf_link *links[NF_INET_NUMHOOKS] = { NULL };
	LIBBPF_OPTS(bpf_netfilter_opts, prerouting_opts, .pf = NFPROTO_IPV4 , .hooknum = NF_INET_PRE_ROUTING, .priority = 200);
	LIBBPF_OPTS(bpf_netfilter_opts, localin_opts, .pf = NFPROTO_IPV4 , .hooknum = NF_INET_LOCAL_IN, .priority = 200);

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

	skel = nf_drop_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF program\n");
		free(values);
		return 1;
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

	printf("Counting packets on %s... Press Ctrl-C to stop.\n", "prerouting");

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
		printf("PRE_ROUTING: packets=%llu bytes=%llu\n", totals[NF_INET_PRE_ROUTING].packets, totals[NF_INET_PRE_ROUTING].bytes);
		printf("LOCAL_IN: packets=%llu bytes=%llu\n", totals[NF_INET_LOCAL_IN].packets, totals[NF_INET_LOCAL_IN].bytes);
	}

cleanup:
	bpf_link__destroy(links[NF_INET_LOCAL_IN]);
	bpf_link__destroy(links[NF_INET_PRE_ROUTING]);
	nf_drop_bpf__destroy(skel);
	free(values);
	return err ? 1 : 0;
}
