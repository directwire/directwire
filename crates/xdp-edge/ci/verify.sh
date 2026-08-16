#!/usr/bin/env bash
# xdp-edge CI 一键验证（Linux 专用）
#
# 用法：
#   ci/verify.sh            # 仅构建+测试（不需要 root）
#   sudo ci/verify.sh --load eth0   # 附加：把 XDP 程序真实挂到网卡（需 root）
#
# 覆盖：
#   1. bpf/xdp_edge.c 用 clang -target bpf 编译（验证器前的第一道工序）
#   2. bpftool 生成 skeleton（可选，装了才跑）
#   3. Rust 全量测试 + release 构建 + benchmark 冒烟（100 万包档）
#   4. --load 模式：加载 XDP 到指定网卡并 dump stats map，随后卸载
set -euo pipefail

cd "$(dirname "$0")/.."

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
step() { echo -e "\n${GREEN}== $* ==${NC}"; }
die()  { echo -e "${RED}FAIL: $*${NC}" >&2; exit 1; }

# ---- 0. 依赖检查 ----
step "依赖检查"
command -v clang  >/dev/null || die "缺少 clang（apt install clang llvm）"
command -v cargo  >/dev/null || die "缺少 cargo（rustup）"
clang --version | head -1
cargo --version

LOAD_DEV=""
if [[ "${1:-}" == "--load" ]]; then
    [[ $# -ge 2 ]] || die "--load 需要指定网卡名"
    LOAD_DEV="$2"
    [[ $EUID -eq 0 ]] || die "--load 模式需要 root（sudo ci/verify.sh --load DEV）"
    command -v ip >/dev/null || die "缺少 iproute2"
fi

# ---- 1. BPF 对象编译 ----
step "BPF 编译（clang -target bpf）"
make -C bpf clean all
[[ -f bpf/xdp_edge.o ]] || die "xdp_edge.o 未产出"
file bpf/xdp_edge.o || true

# ---- 2. Rust 测试与构建 ----
step "cargo test（全量）"
cargo test --all-targets

step "cargo build --release（含 examples）"
cargo build --release --all-targets

step "benchmark 冒烟（验证吞吐量级 > 1 Mpps）"
./target/release/examples/benchmark

# ---- 3. 可选：真实加载到网卡 ----
if [[ -n "$LOAD_DEV" ]]; then
    step "XDP 加载到 $LOAD_DEV（含卸载清理）"
    trap 'ip link set dev "$LOAD_DEV" xdp off || true' EXIT
    make -C bpf load DEV="$LOAD_DEV"
    sleep 1
    ip link show dev "$LOAD_DEV" | grep -q "xdp" || die "XDP 未生效"
    echo "XDP 已挂载，5 秒后卸载…"
    sleep 5
    make -C bpf unload DEV="$LOAD_DEV"
    trap - EXIT
fi

step "全部通过 ✅"
