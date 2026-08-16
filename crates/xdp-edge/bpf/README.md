# bpf/ —— XDP 内核数据面（形态一）

本目录是 xdp-edge 的 Linux 内核侧实现。

> **本机工具链脚注（2026-08）**：开发机为 Windows，LLVM 已装（`winget install LLVM.LLVM`，
> clang 22.1.8）。`clang -target bpf` 本机可用——已验证能以 `-O2 -Wall -Werror`
> 产出合法 BPF 对象（`.text`/`xdp`/`license` 段齐全）。但 `xdp_edge.c` 依赖 Linux
> 内核头文件（`<linux/*.h>`、`<bpf/bpf_helpers.h>`），Windows 本机无此头文件，
> 完整编译与真内核加载/数据面验证在 CI 完成（见「CI 实测」）。如需本机完整构建，
> 在 WSL/容器内执行下方「构建」命令即可。

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
| `ci_datapath_test.py` | CI 真内核数据面实测：编译 → veth 挂载 → 注入包验证 XDP_TX 转发 / XDP_DROP 限速 / stats 计数 |

## CI 实测（ubuntu runner 真内核）

`.github/workflows/bpf.yml` 在每次改动 bpf/ 时自动执行，不需要任何实机设备：

1. `make` —— `clang -target bpf -O2 -Wall -Werror` 编译，产出 `xdp_edge.o`；
2. `ci_datapath_test.py` —— 建 veth 对挂 XDP（验证器接受即加载成功），预填
   `config`/`backends`/`conntrack`，从 veth1 注入自制 TCP SYN，断言收到 IPIP
   封装后的 XDP_TX 转发包（外层 proto=4、saddr=网关、daddr=后端、内层 TCP 保留）；
3. 再把限速速率归零注入新源 IP，断言被 XDP_DROP 且 `stats[ST_DROP_RATE]` 增长；
4. ICMP ping 穿过钩子（PASS 路径）作旁证。

这说明整条「解析→限速→连接跟踪→封装→转发 / 丢弃」数据面在真实内核里跑通，
不只是编译过。测试脚本为纯 python3 标准库 + `iproute2`/`bpftool`，可在任意
Linux 机器（`sudo python3 ci_datapath_test.py`）复现。

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
- **校验和**：外层 IPv4 头纯算术手算（RFC 1071，`xdp_edge.c::ip_checksum`）——`bpf_csum_diff` 不在 XDP 可用 helper 列表，硬用会在验证器加载阶段失败（内层头未改动，无需 `bpf_l3_csum_replace`）；
- **限速 map 满**：`ratelimit` 为 LRU_HASH，内核在满时自动淘汰最久未活跃源（update 不因满失败）；`rl_state.occupancy` 原子计数插入过的源数，超过 `RATELIMIT_SIZE` 即计 `ST_RL_EVICT` 供控制面告警扩容；
- **连接 TTL**：依赖 LRU 淘汰 + 控制面周期清扫（Rust 侧 `control::sweeper` 已实现该节奏），数据面 lookup 路径做惰性过期兜底；
- Maglev LUT 由控制面双缓冲构建后热下发（Rust 侧 `control::lut_publish` 已实现原子切换语义），数据面不参与构建（与 Katran 一致）。
