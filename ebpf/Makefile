CC          ?= gcc
CLANG       ?= clang
LLVM_STRIP  ?= llvm-strip
CFLAGS      ?= -Wall -Wextra -O2
LDFLAGS     ?= -lbpf -lpthread

ARCH        := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	       -I/usr/include/$(shell uname -m)-linux-gnu

TARGET      := bloom_bench_kern_mc
BPF_OBJ     := bloom.bpf.o

.PHONY: all clean bpf

all: $(TARGET) bpf

bpf: $(BPF_OBJ)

$(TARGET): bloom_bench_kern_mc.c $(BPF_OBJ)
	$(CC) $(CFLAGS) -o $@ bloom_bench_kern_mc.c $(LDFLAGS)

$(BPF_OBJ): bloom.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f $(TARGET) $(BPF_OBJ)
