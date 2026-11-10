MODULE_NAME := xdp_counter
BOOTSTRAP ?= ../02-libbpf-bootstrap/libbpf-bootstrap
BOOTSTRAP_OUTPUT := $(BOOTSTRAP)/examples/c/.output
VMLINUX_DIR := $(BOOTSTRAP)/vmlinux.h/include/x86

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 \
	-I$(BOOTSTRAP_OUTPUT) -I$(VMLINUX_DIR)
CFLAGS := -g -O2 -Wall -I$(BOOTSTRAP_OUTPUT)


$(MODULE_NAME): $(MODULE_NAME).o $(BOOTSTRAP_OUTPUT)/libbpf.a
	gcc $^ -lelf -lz -o $@

$(MODULE_NAME).o: $(MODULE_NAME).c $(MODULE_NAME).h $(MODULE_NAME).skel.h
	gcc $(CFLAGS) -c $< -o $@

$(MODULE_NAME).skel.h: $(MODULE_NAME).bpf.o
	bpftool gen skeleton $< > $@

$(MODULE_NAME).bpf.o: $(MODULE_NAME).bpf.c $(MODULE_NAME).h
	clang $(BPF_CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(MODULE_NAME) *.o *.skel.h
