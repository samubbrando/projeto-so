SRC := src

CC := clang
CFLAGS := -O2 -g -target bpf -I$(SRC)
BPFTOOL := bpftool
USER_CC := clang
USER_CFLAGS := -I/usr/include/x86_64-linux-gnu -I$(SRC)
USER_LDLIBS := -lbpf -lelf -lz
RTT_BPF_C := $(SRC)/bpf/rtt.bpf.c
RTT_BPF_O := $(SRC)/bpf/rtt.bpf.o
RTT_SKEL  := $(SRC)/bpf/rtt.skel.h
CG_BPF_C  := $(SRC)/bpf/cgroup_skb.bpf.c
CG_BPF_O  := $(SRC)/bpf/cgroup_skb.bpf.o
CG_SKEL   := $(SRC)/bpf/cgroup_skb.skel.h
USER_C    := $(SRC)/main.c
TARGET    := rtt

VMLINUX_H := $(SRC)/bpf/vmlinux.h

.PHONY: all clean vmlinux

all: $(TARGET)

vmlinux:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

$(VMLINUX_H):
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(RTT_BPF_O): $(RTT_BPF_C) $(SRC)/common/hist.h $(SRC)/bpf/vmlinux.h
	$(CC) $(CFLAGS) -c $< -o $@ \
	    -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types

$(RTT_SKEL): $(RTT_BPF_O)
	$(BPFTOOL) gen skeleton $< > $@

$(CG_BPF_O): $(CG_BPF_C) $(SRC)/common/monitor.h $(SRC)/bpf/bpf_common.h $(SRC)/bpf/vmlinux.h
	$(CC) $(CFLAGS) -c $< -o $@ \
	    -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types

$(CG_SKEL): $(CG_BPF_O)
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET): $(USER_C) $(RTT_SKEL) $(CG_SKEL)
	$(USER_CC) $(USER_CFLAGS) -o $@ $< $(USER_LDLIBS)

clean:
	rm -f $(RTT_BPF_O) $(RTT_SKEL) $(CG_BPF_O) $(CG_SKEL) $(VMLINUX_H) $(TARGET)