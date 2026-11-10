#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "xdp_counter.h"
#include "xdp_counter.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
	stop = 1;
}

static int read_totals(struct xdp_counter_bpf *skel, struct counters *values,
		       int ncpus, struct counters *total)
{
	unsigned int key = 0;
	int err, i;

	err = bpf_map__lookup_elem(skel->maps.stats, &key, sizeof(key), values,
				   sizeof(*values) * ncpus, 0);
	if (err)
		return err;

	total->packets = 0;
	total->bytes = 0;
	for (i = 0; i < ncpus; i++) {
		total->packets += values[i].packets;
		total->bytes += values[i].bytes;
	}
	return 0;
}


int main(int argc, char **argv)
{
	struct xdp_counter_bpf *skel;
	struct counters *values = NULL;
	struct counters total;
	unsigned int ifindex;
	int ncpus;
	int err = 0;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
		return 1;
	}

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		perror("if_nametoindex");
		return 1;
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

	skel = xdp_counter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF program\n");
		free(values);
		return 1;
	}

	// Attach the XDP program to the specified interface
	// Note: This assumes that the XDP program is named "count_packets" in the BPF skeleton
	// The attach function will return a link object that can be used to detach the program later (release)
	skel->links.count_packets = bpf_program__attach_xdp(skel->progs.count_packets, ifindex);
	if (!skel->links.count_packets) {
		err = -errno;
		fprintf(stderr, "Failed to attach XDP program: %d\n", err);
		goto cleanup;
	}

	printf("Counting packets on %s... Press Ctrl-C to stop.\n", argv[1]);

	while (!stop) {
		sleep(1);

		err = read_totals(skel, values, ncpus, &total);
		if (err) {
			fprintf(stderr, "Failed to read counters: %d\n", err);
			break;
		}
		printf("packets=%llu bytes=%llu\n", total.packets, total.bytes);
	}

cleanup:
	xdp_counter_bpf__destroy(skel);
	free(values);
	return err ? 1 : 0;
}
