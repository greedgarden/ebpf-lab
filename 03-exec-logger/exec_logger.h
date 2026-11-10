#ifndef EXEC_LOGGER_H
#define EXEC_LOGGER_H

#define COMM_LEN 16
#define FILENAME_LEN 256

struct event {
	int pid;
	char comm[COMM_LEN];
	char filename[FILENAME_LEN];
};

#endif
