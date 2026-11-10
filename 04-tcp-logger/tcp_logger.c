#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "tcp_logger.h"
#include "tcp_logger.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
	stop = 1;
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct event *e = data;
	char saddr[INET_ADDRSTRLEN];
	char daddr[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, e->saddr, saddr, sizeof(saddr));
	inet_ntop(AF_INET, e->daddr, daddr, sizeof(daddr));

	printf("%d %s %s -> %s:%u\n", e->pid, e->comm, saddr, daddr, e->dport);

	return 0;
}

int main(void)
{
	struct tcp_logger_bpf *skel;
	struct ring_buffer *rb = NULL;
    struct stat sb;
	int err;

    setvbuf(stdout, NULL, _IOLBF, 0);

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	if (stat("/proc/self/ns/pid", &sb)) {
		perror("stat /proc/self/ns/pid");
		return 1;
	}

	skel = tcp_logger_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF program\n");
		return 1;
	}

	skel->rodata->pidns_dev = sb.st_dev;
	skel->rodata->pidns_ino = sb.st_ino;
	printf("%lu %lu\n", sb.st_dev, sb.st_ino);

	err = tcp_logger_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF program: %d\n", err);
		goto cleanup;
	}

	err = tcp_logger_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "Failed to create ring buffer: %d\n", err);
		goto cleanup;
	}

	printf("Tracing TCP connects... Press Ctrl-C to stop.\n");

	while (!stop) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Failed to poll ring buffer: %d\n", err);
			break;
		}
		err = 0;
	}

cleanup:
	ring_buffer__free(rb);
	tcp_logger_bpf__destroy(skel);
	return err ? 1 : 0;
}
