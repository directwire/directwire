# bpf/ —— XDP 内核数据面（形态一）

本目录是 xdp-edge 的 Linux 内核侧实现，需在 Linux 上构建（本仓库开发机为 Windows，无 clang，故此处交付源码 + 构建脚本，由 CI / 目标一体机执行构建）。

## 构建

```bash
# Ubuntu 22.04+
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -m)-linux-gnu bpftool
cd bpf
make            # 产出 xdp_edge.o（+ 可选 bpftool skeleton）
```

## 加载 / 卸载

```bash
sudo make load DEV=eth0     # 挂到 eth0 的 XDP 钩子
sudo make unload DEV=eth0
```

## 结构

| 文件 | 说明 |
|---|---|
| `xdp_edge.c` | XDP 主程序：解析 → 令牌桶限速 → SYN flood 检测 → 连接跟踪 → Maglev 查表 → IPIP 封装 XDP_TX |
| `xdp_edge.h` | 控制面/数据面共享 ABI：maps、配置、统计下标 |
| `Makefile` | `clang -target bpf` 构建与 `ip link` 加载 |

## 与用户态模拟器的对应关系

| BPF map / 逻辑 | Rust 模块 |
|---|---|
| `maglev_lut`（ARRAY）| `src/maglev.rs`（构建算法）+ `src/control/lut_publish.rs`（双缓冲热下发） |
| `conntrack`（LRU_HASH）| `src/conntrack.rs` + `src/control/sweeper.rs`（TTL 清扫） |
| `ratelimit`（令牌桶）| `src/token_bucket.rs` |
| `syn_track`（滑动窗口）| `src/synflood.rs` |
| `xdp_edge_main` 判决管线 | `src/simulator.rs::process` |
| 健康检查 / 邻居解析 / 配置下发 | `src/control/`（agent 骨架） |

## 已知简化（产品化 TODO）

- **MAC 重写已实现，解析委托控制面**：XDP_TX 回注前将 `eth->h_dest/h_source` 重写为 `backend_info.dmac` / `config.gateway_smac`；dmac 全 0（控制面尚未 ARP 解析）时丢包并计 `ST_DROP_NOMAC`，不会把坏帧发上链路；
- **校验和**：外层 IPv4 头用 `bpf_csum_diff` + 手动折叠计算（内层头未改动，无需 `bpf_l3_csum_replace`）；
- **限速 map 满**：`ratelimit` 为 LRU_HASH，内核在满时自动淘汰最久未活跃源（update 不因满失败）；`rl_state.occupancy` 原子计数插入过的源数，超过 `RATELIMIT_SIZE` 即计 `ST_RL_EVICT` 供控制面告警扩容；
- **连接 TTL**：依赖 LRU 淘汰 + 控制面周期清扫（Rust 侧 `control::sweeper` 已实现该节奏），数据面 lookup 路径做惰性过期兜底；
- Maglev LUT 由控制面双缓冲构建后热下发（Rust 侧 `control::lut_publish` 已实现原子切换语义），数据面不参与构建（与 Katran 一致）。
