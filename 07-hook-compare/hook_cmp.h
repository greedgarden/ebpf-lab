#ifndef HOOK_CMP_H
#define HOOK_CMP_H

typedef enum {
	CMP_HOOK_PREROUTING = 0,
	CMP_HOOK_LOCALIN,
	CMP_HOOK_XDP,
	CMP_HOOK_TC,
	CMP_HOOK_NUM,
} CMP_HOOK_T;

#define DROP_PROTO_MAX 10
typedef struct {
	__u32 num;
	__u8 proto[DROP_PROTO_MAX];
} DROP_RULES;

struct counters {
	__u64 packets;
	__u64 bytes;
	__u64 drops;
};

#endif
