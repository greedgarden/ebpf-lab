#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "exec_logger.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

const volatile __u64 pidns_dev = 0;
const volatile __u64 pidns_ino = 0;

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct bpf_pidns_info ns;
	struct event *e;

    if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns)))
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = ns.tgid;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
				(const char *)ctx->args[0]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
