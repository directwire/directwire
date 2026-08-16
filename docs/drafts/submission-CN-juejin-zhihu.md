# 海外三代网络架构 + 国密抗量子：一套开源协议栈的降维实践

> **草稿 —— 未发布。** 目标渠道：掘金 / 知乎专栏。文中所有数字都可以溯源到
> [v0.3「证据链」Release](https://github.com/directwire/directwire/releases/tag/v0.3)
> 和[架构白皮书](https://github.com/directwire/directwire/blob/main/docs/architecture-whitepaper.md)。
> Directwire 是匿名组织仓库，无个人署名。

**TL;DR ——** 海外网络已经走到第三代：TCP → QUIC → Homa/MoQ。我们用 Rust 开源了
一整套五层协议栈：**国密 + 后量子**混合安全通道 → 公钥寻址 P2P 网格 → Media-over-QUIC
直播传输 → Homa 式消息导向 RPC → 给中继基础设施挡 DDoS 的 eBPF/XDP 数据面。
五层五个 crate，各层可独立验证，全部共享一条线上。v0.3 的铁律：**每个数字都带测量
装置**（loopback / 确定性网络模拟 / 真内核），没有一个数字是 PPT。

---

## 为什么现在做这件事：一个 ≈0% 的窗口

先说动机，这是整个项目的起点。

中国关键信息基础设施（关基）的**后量子（PQ）部署率 ≈ 0%**。国产 PQC 国标预计
**2027–2029** 才落地；NIST 到 **2030** 弃用纯经典算法；海外 PQ 流量占比已经
**>60%**。这个时间差就是窗口：

> 标准真空期里，事实标准 = 谁写得最好、测得最透。

TLS 层的国密混合握手已经有人做了（铜锁 / 零信任浏览器走的正是 SM2MLKEM768，
IANA 4590）。但那只把一个 KEM 塞进 TLS 扩展点。我们要的是**整条线**：握手本身就是
传输，会话层是 SM4-GCM + 抗重放 + 抗 DoS cookie + PSK/0-RTT，上层（网格、直播、
RPC）消费的是**整个会话**，不是 TLS 的一个 flag。国标落地时，`kem` trait 把
ML-KEM-768 换成本土 PQC 组件——**换算法不换架构**。

## 降维：海外第三代网络架构，直接做成开箱可跑的

海外网络架构演进：

1. **TCP** —— 字节流、连接语义、队头阻塞，把短请求的尾延迟拖死。
2. **QUIC** —— 内核旁路、0-RTT、多路复用，海外已大规模落地。
3. **Homa / MoQ** —— 数据中心级**消息导向**传输（换掉 TCP）+ **对象流订阅**直播
   （换掉 HLS）。Homa 上游还是 Linux 内核补丁，MoQ 是 IETF 还在跑的草案，海外
   Cloudflare 已经 330+ 城市跑 MoQ，NAB 2026 有 11 家厂商互通——**中国参与 = 0**。

我们的降维实践：**不做内核补丁，做纯用户态**。Homa 的 IANA 协议号（146）我们不用，
用 UDP 承载；直播协议按 MoQ-lite 子集实现。部署楔子就是「免内核补丁」。

## 五层协议栈

| 层 | crate | 职责 | 测试 |
|---|---|---|---|
| **安全** | `gm-pq-stack` | SM2 + ML-KEM-768 混合握手、SM4-GCM 会话、抗重放窗口、cookie 抗 DoS、PSK/0-RTT | 46 |
| **连通** | `p2p-mesh` | 公钥寻址网格：按 NodeId 拨号、中继代理、NAT 打洞、QUIC 双端直连、自适应路径、MCP 服务 | — |
| **媒体** | `moq-live` | MoQ-lite 订阅直播：按组发流、优先级丢包、追帧补包 | 39 |
| **RPC** | `homa-rpc` | Homa 式消息导向传输 over UDP + 幂等 RPC：SRPT 授权调度、8 级 QoS | 20 |
| **边缘** | `xdp-edge` | eBPF/XDP 边缘数据面：源限速、SYN 洪水检测、Maglev 负载均衡、IPIP 转发 | 31 |

全工作区 **≈180 个测试**，`cargo test --workspace --all-features` 一键全跑。
「写得最好、测得最透」不是口号，是仓库里每条 CI 都在执行的东西。

## 逐层讲

### 1. 安全层：`gm-pq-stack` —— 混合握手就是传输本身

混合握手走 Noise-XX 三消息形态：经典腿用 SM2-ECDH（GB/T 32918），后量子腿用
ML-KEM-768（FIPS 203），SM3 做组合器（GHP18/X-wing 风格）。安全论证是标准的
「最强腿获胜」：攻击者必须**两腿全破**。会话面全在国密族：SM4-GCM、SM3-HKDF、
64 槽滑动抗重放窗口、WireGuard 式无状态 cookie、PSK 会话恢复。所有密钥离开作用域即
zeroize。

SM2MLKEM768 不是我们发明的（IANA 4590，铜锁和零信任浏览器已有），**我们赢在
层级**：不是 TLS 栈里的一处 KEM，而是整条端到端安全通道——上层消费「会话」，不消费
「扩展点」。

### 2. 连通层：`p2p-mesh` —— 身份就是地址

NodeId **就是** ed25519 公钥，拨号只认公钥：没有 DNS、没有注册中心、没有 CA、没有
账号。传输只有两个角色：**中继**（保活）和**直连**（打洞后的 QUIC 路径）。路径选择由
栈来做，不由 agent 做：`eff = RTT × (1 + 10 × 丢包)` + 滞回 + 最小驻留窗，中继保持
热连接，直连挂了优雅降级。打洞的 UDP socket 就是 QUIC socket，双端同时打开不需要
客户端/服务端角色。

会话层有双身份：NodeId 是 ed25519，混合握手却认证 SM2 公钥。**BIND 签名**
（`"p2p-mesh/gmpq-bind" || SM3(gm_pk) || node_id || session_id`）击穿拼接式中间人：
`session_id` 由握手转录派生，被拼接的握手两半各自得到不同的 ID，转发 BIND 必然校验失败。

这层还带 **MCP 服务**：网格以 MCP 工具的形式暴露给 agent 工具链（stdio）。
「按公钥拨号」不再是库属性，而是可调用的工具。

### 3. 媒体层：`moq-live` —— 直播从拉流到订阅

直播正从「文件分片拉取」（HLS/LL-HLS，2–5 秒）迁到「对象流订阅」（MoQ，0.3–1 秒）。
`moq-live` 是可跑的 MoQ-lite 骨架：varint 帧编解码、namespace/track/group/object
寻址、按组发流数据面、中继即缓存带追帧、优先级丢包（拥塞时先丢 P 帧再丢 I 帧）。
媒体面是 QUIC 订阅图——和每一层一样，可以包进 `gm-pq` 混合会话。

### 4. RPC 层：`homa-rpc` —— 用户态 Homa，短 RPC 全档位碾压 TCP

Homa（斯坦福）是要替换数据中心 TCP 的消息导向传输，上游还是 Linux 内核补丁。我们做
**纯用户态 over UDP** 的 Homa-lite：消息导向 `send_to(msg)/recv()`、首 10KB 未调度
窗口（短 RPC 永远 1 个 RTT）、接收端 GRANT 调度（SRPT、overcommit K=2、防饿死）、
8 级 QoS 队列、RESEND 批量重传、at-least-once + 幂等去重。两个核心状态机
（SenderCore/ReceiverCore）**不碰 socket**——确定性单测是架构属性，不是补丁。

loopback 混合负载实测（550 调用，91% 短 100B + 9% 长 1MiB，8 线程）：短 RPC **P50
快 2.7×**（520µs vs 1.4ms）、P90 快 1.9×、P99 快 1.2×，总墙钟**快 30%**。长消息付
SRPT 让位的结构性税（~1.7× 慢）——这是让短消息插队的代价。

### 5. 边缘层：`xdp-edge` —— 中继基础设施的守门人

中继是常在线部分，常在线就是被打的部分。`xdp-edge` 是 Katran/Unimog 血统的
eBPF/XDP 数据面：源令牌桶、SYN 洪水检测、conntrack LRU、Maglev 一致性哈希（后端故障
扰动 ≈1/N）、IPIP 转发。XDP 在 skb 分配前运行（第三方实测 P99 ~4µs vs iptables
~125µs），控制面原子热换 Maglev LUT。

可复现性纪律是它的双重形态：内核 `bpf/` 源码（CI 里 clang 编译）+ **逐行镜像同一
决策管线的 Rust 用户态模拟器**（任何开发机都能验证）。「5.2 Mpps，无 DPDK 机」因此是
可测声明不是 PPT——实测 4.66–4.89 Mpps，单包 P50 200ns / P99 700ns。

## v0.3 证据矩阵

每个数字都带测量装置。🔁 loopback · 🌐 net-sim（真实 socket + 确定性延迟/丢包注入，
多机测试床的 80% 替身）· 🐧 真内核 · ✅ CI · 📚 第三方。

| # | 声明 | 证据 | 级别 |
|---|---|---|---|
| 1 | ≈180 测试，各层独立可验证 | CI `cargo test --workspace --all-features` 全绿 | ✅ CI |
| 2 | 短 RPC P50 2.7× / P90 1.9× / P99 1.2×，总墙钟 −30% | loopback 混合负载 | 🔁 loopback |
| 3 | 长消息 38ms → 4.6ms（初版 73ms 起 ≈16×） | benchmark + trace_probe/mix_probe | 🔁 loopback |
| 4 | 100ms RTT 长消息 **5.34×** vs TCP（322ms vs 1717ms） | net-sim 100ms-RTT profile | 🌐 net-sim |
| 5 | 100ms RTT + 1% 丢包仍 **4.66×** | net-sim 1%-loss profile | 🌐 net-sim |
| 6 | 短消息单包丢失死区闭合：P99 5.1s → **453ms**，无丢包零额外重发 | net-sim + 确定性单测 | 🌐 net-sim + ✅ |
| 7 | 10ms RTT + 5% 丢包：273 条短 RPC **0 失败**（v0.1：2 失败、P99≈10s） | net-sim 5%-loss profile | 🌐 net-sim |
| 8 | xdp-edge 数据面真内核正确运行 | bpf CI：veth 加载 + **XDP_TX 环回**（解析→限速→连接跟踪→Maglev→IPIP→XDP_TX 全链） | 🐧 真内核 |
| 9 | 74B IPIP 帧字节级正确 | runner 内核 veth 不携带 adjust_head 修改（已文档化），字节由 Rust 模拟器校验，保留修改的内核上走完整断言 | 🔁 模拟器 |
| 10 | Katran 同级 ~5.2Mpps「无 DPDK 机」→ 实测 4.66–4.89 Mpps | xdp-edge benchmark（10⁷ 包，单线程 release） | 🔁 模拟器 |
| 11 | XDP P99 ~4µs vs iptables ~125µs | 第三方公开测量（引注，非本项目实测） | 📚 第三方 |
| 12 | Maglev 故障扰动 ≈1/N、存活连接误迁移 <1% | 单元/集成测试 | 🔁 模拟器 |
| 13 | fuzz：5 目标 10 分钟零崩溃（~10⁹ 迭代） | fuzz CI（libFuzzer smoke + nightly） | ✅ CI |
| 14 | gmpq 密钥不烧迭代预算 | `KeyPool` OnceLock 预生成 8+8 密钥，迭代触达 decap/AEAD-open 深层状态 | ✅ 代码+单测 |

## 16× 攻坚故事

一条 1MiB RPC，loopback：**初版 73ms → 基线后 38ms → 现在 4.6ms。≈16×。**

1. **GSO 发送批量 + GRO 接收批量** —— 每次系统调用扛更多分片。
2. **ahash 热映射** —— 每包查找路径。
3. **零拷贝发送** —— API 收走移动的 `Vec`，发借用切片。
4. **固定 worker 池** —— 服务端不再每调用起线程。

更值钱的是后面这段：我们一度以为下一个大饼是「把分片构建移出 io_loop 锁」。**先测了
再动手**——`io_lock_avg_batch` 持锁 16.9µs、**等锁 0.6µs**。锁根本不是瓶颈。真正的
开销是每分片 `Packet::encode` 的一次 memcpy（≈250ns × 874 ≈ 200µs/1MiB 方向）。正解
是 `sendmsg` header iovec + 负载切片（内核聚集）。那是核心路径上 ~20% 的收益，所以跟
多机测试床一起排期，不在单机 loopback 上赌。**测量优先，别拍脑袋重构。**

## 诚实边界

- `gm-pq-stack` 是干净房间的参考骨架，**未认证**——等保评估与商用密码认证是明确红线，
  生产须换认证模块/密码卡。
- Homa 长消息并发是最弱层：单 IO 线程，io_uring/AF_XDP 旁路 + 多线程 IO 是开放方向。
- `moq-live` 是 draft-ietf-moq-transport-17 的子集：无 datagram track、单发布者拓扑、
  无跨中继去重。
- `xdp-edge` 控制面是骨架，探活由虚拟时钟驱动。
- **多机真实网卡实测是待办**——net-sim 是 80% 替身，我们在文档里写明。

## 上手

```bash
git clone https://github.com/directwire/directwire
cd directwire
cargo test --workspace --all-features   # ≈180 个测试
cargo run --release -p homa-rpc --example benchmark    # loopback 对打 TCP
cargo run --release -p homa-rpc --example net_probe    # 网络条件探测
```

—

**Directwire** —— 为 AI agent 提供直接、加密、无服务器的通信基础设施的开源协议与
参考实现。**按公钥拨号，不按 IP。**

- GitHub：https://github.com/directwire/directwire
- v0.3 Release（上文证据矩阵的复现命令全在里面）：
  https://github.com/directwire/directwire/releases/tag/v0.3
