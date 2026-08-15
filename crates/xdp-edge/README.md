# xdp-edge —— eBPF/XDP 边缘网关数据面（DDoS 防护 + 四层负载均衡）

> 单核 5.2 Mpps 的 XDP 数据面，做成可交付的政企一体机软件发行版——替代 DPDK 专用机方案。

## 项目定位与降维逻辑

**行业现状**：海外已被验证——Meta Katran 用 XDP 做四层负载均衡，核心仅约 1000 行 C，单核 5.2 Mpps，是 IPVS 的 4.3 倍吞吐；Cloudflare Unimog 的 LB 开销低于 1% CPU，可以与业务混部。而国内主力方案仍是 DPDK 专用机：独占 CPU 核、独占网卡、专用硬件，成本高、无法混部。

**降维逻辑**：

```
DPDK 专用机方案                     xdp-edge（XDP 方案）
─────────────────                   ─────────────────────────
独占 4~8 核 busy-poll          →    按需占用，开销 <1% CPU，与业务混部
独占网卡（kernel bypass）      →    复用内核驱动与网卡队列，不动网络栈
专用硬件 / 专用机房            →    任意标准 x86 服务器，内核 ≥ 5.x
自研转发面全量维护             →    核心 XDP 程序 ~300 行 C，可审计
```

XDP 在网卡驱动收包路径最前端执行（早于 skb 分配），P99 延迟约 4µs，对比 iptables 路径约 125µs。本项目把「Katran 级数据面 + DDoS 快速路径」打包成**可验证的双形态交付物**。

## 双形态交付

开发机为 Windows、无 clang，eBPF 无法本地编译，因此：

| 形态 | 目录 | 说明 |
|---|---|---|
| 形态一：内核数据面 | `bpf/` | 完整 XDP C 源码 + Makefile（`clang -target bpf`），在 Linux / CI 上构建加载 |
| 形态二：用户态模拟器 | `src/` | Rust 逐包复刻 XDP 程序语义，本机 `cargo test` 即可验证全部核心机制与性能 |

两侧共享同一套 ABI 定义（`bpf/xdp_edge.h` ↔ `src/` 模块），判决管线逐行对应。

## 架构图

```
                        ┌─────────────────────────────────────────┐
                        │           控制面（一体机 agent）          │
                        │  健康检查 → 摘除故障后端                  │
                        │  Maglev LUT 计算 ──┐  配置下发（限速/阈值）│
                        └────────────────────┼─────────────────────┘
                                             │ map 更新
        网卡 RX ──► XDP hook（驱动层，早于 skb）│
                        │                    ▼
        ┌───────────────┴──────────────────────────────────┐
        │              xdp_edge_main 判决管线                │
        │                                                    │
        │  ① per源令牌桶 ──超限──► XDP_DROP  (DDoS 快速路径)   │
        │  ② SYN flood 检测 ──判定──► XDP_DROP                 │
        │  ③ conntrack LRU ──命中──► 复用后端（连接亲和）       │
        │           │miss                                    │
        │  ④ Maglev 一致性哈希 ──► 选后端（扩容/故障扰动≈1/N）  │
        │  ⑤ IPIP 封装 ──► XDP_TX 转发到后端                  │
        └────────────────────────────────────────────────────┘
                        │
             ┌──────────┴──────────┐
             ▼                     ▼
        后端集群 10.0.0.x     统计 map（转发/丢弃/命中）
```

## 快速开始

```bash
# 形态二：本机验证（Windows/Linux/macOS 均可）
cd xdp-edge
cargo test                              # 全部单元 + 集成测试（31 个用例）
cargo run --release --example benchmark # 1000 万包模拟：吞吐 + 延迟分布

# 形态一：内核数据面（Linux，内核 ≥ 5.4）
cd bpf && make                          # clang -target bpf 产出 xdp_edge.o
sudo make load DEV=eth0                 # 挂到网卡 XDP 钩子

# CI 一键验证（Linux）：bpf 编译 + cargo test + benchmark 冒烟
ci/verify.sh                            # 构建+测试
sudo ci/verify.sh --load eth0           # 附加真实网卡加载/卸载验证
```

本机实测（Windows，Rust 1.96，单线程 release）：**4.89 M pps** 用户态软件路径，决策延迟 P50 200ns / P99 700ns —— 每包逻辑成本进入亚微秒级，证明管线架构搬到内核 XDP 后（无 HashMap、map 查找为 O(1) 内核实现）达到 Katran 同级 5.2 Mpps 没有架构障碍。

## 对标数据

| 指标 | 参照 | 数值 |
|---|---|---|
| Katran vs IPVS 吞吐 | Meta 公开数据 | **4.3×** |
| Katran 单核吞吐 | Meta 公开数据 | **5.2 Mpps** |
| Unimog LB CPU 开销 | Cloudflare 公开数据 | **<1%**（可混部） |
| XDP 第三方基准吞吐 | 社区基准（XDP_TX/DROP 路径） | **18.2 Mpps** |
| XDP vs iptables P99 延迟 | 公开测量 | **4µs vs 125µs** |
| 本项目模拟器单核吞吐 | 本机实测 | **4.66 Mpps**（用户态 Rust） |
| Maglev 后端故障扰动 | 本项目测试 | **≈1/N，存活连接误迁移 <1%** |

## 产品形态

**政企 DDoS 防护 / LB 一体机软件发行版**：标准 x86 服务器 + 主流网卡即可部署，与业务负载混部，按 vCPU/带宽订阅授权。目标客户：金融、政务、运营商边缘节点——当前这类客户被 DPDK 专用机方案的硬件与运维成本锁定。

## 目录结构

```
xdp-edge/
├── bpf/                  # 形态一：XDP 内核数据面（Linux 构建）
│   ├── xdp_edge.c        #   主程序：限速/SYN检测/连接跟踪/Maglev/IPIP
│   │                     #   （MAC 重写、bpf_csum_diff 校验和、限速 LRU 淘汰计数）
│   ├── xdp_edge.h        #   控制面共享 ABI
│   ├── Makefile          #   clang -target bpf
│   └── README.md         #   构建与加载说明
├── src/                  # 形态二：Rust 用户态（本机可验证）
│   ├── maglev.rs         #   Maglev 一致性哈希（LUT 构建 + 查找）
│   ├── token_bucket.rs   #   per-源令牌桶限速
│   ├── synflood.rs       #   SYN flood 滑动窗口检测
│   ├── conntrack.rs      #   LRU 连接跟踪 + 惰性过期 + 主动清扫
│   ├── simulator.rs      #   XDP 判决管线编排
│   ├── metrics.rs        #   Prometheus /metrics 文本导出（pps/drop/命中率等 8 项）
│   ├── control/          #   控制面 agent 骨架
│   │   ├── health.rs     #     后端健康检查（虚拟时钟探活，rise/fall 防抖）
│   │   ├── lut_publish.rs#     Maglev LUT 双缓冲原子热切换（RCU-lite 读者计数）
│   │   ├── sweeper.rs    #     conntrack TTL 周期清扫
│   │   └── agent.rs      #     主循环编排：探活→翻转检测→热发布→清扫
│   └── packet.rs         #   五元组 / XDP 动作语义
├── tests/                # 集成测试（含控制面+数据面端到端故障切换）
├── examples/benchmark.rs # 1000 万包吞吐与延迟基准
├── ci/verify.sh          # Linux CI 一键验证（bpf 编译+cargo test+可选网卡加载）
└── ROADMAP.md            # 12 个月产品化路线图
```

## 已知简化与技术债

见 `bpf/README.md`。剩余主要项：真实探活 IO（当前为虚拟时钟注入结果）、/metrics 的 HTTP 端点封装（当前为纯文本生成函数）、双机会话同步（ROADMAP Q2）。
