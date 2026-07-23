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
XDP_BPF_C := $(SRC)/bpf/xdp.bpf.c
XDP_BPF_O := $(SRC)/bpf/xdp.bpf.o
XDP_SKEL  := $(SRC)/bpf/xdp.skel.h
TC_BPF_C  := $(SRC)/bpf/tc.bpf.c
TC_BPF_O  := $(SRC)/bpf/tc.bpf.o
TC_SKEL   := $(SRC)/bpf/tc.skel.h
USER_C    := $(SRC)/main.c
TARGET    := scheduler

VMLINUX_H := $(SRC)/bpf/vmlinux.h

.PHONY: all clean vmlinux

all: $(TARGET)

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

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

$(XDP_BPF_O): $(XDP_BPF_C) $(SRC)/common/monitor.h $(SRC)/bpf/bpf_common.h $(SRC)/bpf/vmlinux.h
	$(CC) $(CFLAGS) -c $< -o $@ \
	    -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types

$(XDP_SKEL): $(XDP_BPF_O)
	$(BPFTOOL) gen skeleton $< > $@

$(TC_BPF_O): $(TC_BPF_C) $(SRC)/common/monitor.h $(SRC)/bpf/bpf_common.h $(SRC)/bpf/vmlinux.h
	$(CC) $(CFLAGS) -c $< -o $@ \
	    -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types

$(TC_SKEL): $(TC_BPF_O)
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET): $(USER_C) $(RTT_SKEL) $(CG_SKEL) $(XDP_SKEL) $(TC_SKEL)
	$(USER_CC) $(USER_CFLAGS) -o $@ $< $(USER_LDLIBS)

clean:
	rm -f $(RTT_BPF_O) $(RTT_SKEL) $(CG_BPF_O) $(CG_SKEL) \
	      $(XDP_BPF_O) $(XDP_SKEL) $(TC_BPF_O) $(TC_SKEL) \
	      $(VMLINUX_H) $(TARGET)
