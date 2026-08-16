# xdp-edge BPF 对象构建
# 依赖：clang >= 12（支持 -target bpf）、libbpf 头文件、bpftool
# Ubuntu: apt install clang llvm libbpf-dev linux-libc-dev iproute2
#         （bpftool 无独立 apt 包，CI 里从 libbpf/bpftool 源码构建；
#          勿用 linux-headers-$(uname -r)：版本耦合且头文件装在 /usr/src）

CLANG    ?= clang
LLC      ?= llc
BPFTOOL  ?= bpftool

# 内核头文件路径（Debian/Ubuntu 常见布局）
KERNEL_HDRS ?= /usr/include/$(shell uname -m)-linux-gnu

CFLAGS   := -O2 -g -target bpf -D__TARGET_ARCH_x86 \
            -Wall -Werror \
            -I$(KERNEL_HDRS) -I.

all: xdp_edge.o

xdp_edge.o: xdp_edge.c xdp_edge.h
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(BPFTOOL) gen skeleton $@ > xdp_edge.skel.h 2>/dev/null || true

# 加载到网卡（需 root；替换 DEV 为实际网卡）
load: xdp_edge.o
	ip link set dev $(DEV) xdp obj xdp_edge.o sec xdp

unload:
	ip link set dev $(DEV) xdp off

clean:
	rm -f xdp_edge.o xdp_edge.skel.h

.PHONY: all load unload clean
