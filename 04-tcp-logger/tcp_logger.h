#ifndef TCP_LOGGER_H
#define TCP_LOGGER_H

#define COMM_LEN 16

struct event {
	int pid;
	char comm[COMM_LEN];
	unsigned char saddr[4];
	unsigned char daddr[4];
	unsigned short dport;
};

#endif
