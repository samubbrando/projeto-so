CC := clang
CFLAGS := -O2 -g -target bpf
BPFTOOL := bpftool
USER_CC := clang
USER_CFLAGS := -I/usr/include/x86_64-linux-gnu
USER_LDLIBS := -lbpf -lelf -lz

SRC := src
BPF_C := $(SRC)/rtt.bpf.c
BPF_O := $(SRC)/rtt.bpf.o
SKEL := $(SRC)/rtt.skel.h
USER_C := $(SRC)/main.c
TARGET := rtt

.PHONY: all clean

all: $(TARGET)

$(BPF_O): $(BPF_C) $(SRC)/hist.h $(SRC)/vmlinux.h
	$(CC) $(CFLAGS) -c $< -o $@ \
	    -Wno-unknown-warning-option -Wno-compare-distinct-pointer-types

$(SKEL): $(BPF_O)
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET): $(USER_C) $(SKEL)
	$(USER_CC) $(USER_CFLAGS) -o $@ $< $(USER_LDLIBS)

clean:
	rm -f $(BPF_O) $(SKEL) $(TARGET)
