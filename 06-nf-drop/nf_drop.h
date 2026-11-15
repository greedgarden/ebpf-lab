#ifndef NF_DROP_H
#define NF_DROP_H

struct counters {
	unsigned long long packets;
	unsigned long long bytes;
	unsigned long long drops;
};

#endif
