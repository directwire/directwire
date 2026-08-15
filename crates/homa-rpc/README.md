# homa-rpc — Homa 消息导向传输的用户态移植 + 极简 RPC

## 定位与降维逻辑

Homa（Stanford, Ousterhout）是要替换数据中心 TCP 的消息导向传输协议。国内 brpc/gRPC 全部跑在 TCP 上，短 RPC 的尾延迟被 TCP 的连接语义、队头阻塞和字节流抽象拖死。本项目用 Rust 在**用户态 over UDP** 上实现 Homa-lite，验证其架构范式可以脱离内核补丁落地为一个 RPC 底座。

相对 TCP 的降维打击点（全部真实实现，非 PPT）：

1. **消息导向而非字节流**：`send_to(msg)` / `recv() -> msg`，无连接、无字节流拼接。
2. **首 RTT 未调度窗口直发**：每条消息前 10KB 不等授权直接发出，短 RPC 永远 1 个 RTT。
3. **接收端驱动 GRANT 调度**：长消息的后续字节必须等接收端 GRANT（累计授权），接收端按**剩余字节数 SRPT** 选择前 K 条授权（overcommit，默认 K=2），短消息可抢占长消息；授权节流（窗口消耗过半才续授）+ 久未授权强制兜底（防饿死）。
4. **8 级动态优先级**：按消息长度映射优先级写入包头；发送侧 8 级 QoS 队列真实插队（`txqueue.rs`），高优先级短消息分片可越过积压的长消息突发先发出。
5. **at-least-once + 幂等去重**：RESEND 批量重传 + RPC 层整请求重试 + 服务端按 rpc_id 去重回放缓存响应。

## 架构

```
        ┌───────────────────────── RpcClient ─────────────────────────┐
        │  call() ──rpc_id 帧──┐        ┌── 分发线程: 按 rpc_id 路由响应 │
        └──────────────────────│────────│─────────────────────────────┘
                               ▼        ▼
        ┌──────────────────────── Transport ────────────────────────┐
        │  SenderCore(纯状态机)            ReceiverCore(纯状态机)      │
        │  · 切分片/未调度窗口直发          · 乱序重组(分片位图)         │
        │  · GRANT→泵送调度分片            · GRANT 调度器(SRPT+overcommit│
        │  · RESEND→重发/补记账            │   抢占+防饿死+授权节流)      │
        │  · 停滞探针 + linger 驻留        · 缺包→RESEND 批量修复       │
        │  TxQueues: 8 级优先级 QoS 插队    · 授权停滞→重发 GRANT        │
        └──────────────│────────────────────────▲────────────────────┘
                       │ UDP 数据报              │  (DATA/GRANT/RESEND/BUSY)
                  ┌────▼─────────────────────────┴────┐
                  │   IO 线程: recv_from + 5ms tick    │
                  └───────────────────────────────────┘

        RpcServer: recv 循环 ──> 幂等去重缓存 ──> 每请求工作线程 ──> 回响应
```

关键工程决策：两个核心状态机**不碰 socket**，输入包、输出 `Action` 列表（Send/Deliver），因此调度器、重组、重传全部可以脱离网络做确定性单测。

## 快速开始

```bash
cargo test                              # 20 个测试：SRPT/重组/重传/RPC 端到端
cargo run --release --example benchmark # loopback 混合负载对比 TCP
```

API 速写：

```rust
let server = RpcServer::spawn("127.0.0.1:0", |req| req.to_vec())?;   // echo 服务
let client = RpcClient::new("127.0.0.1:0")?;
let resp = client.call(server.addr(), b"ping")?;                     // at-least-once
```

## 对标数据

| 指标 | Homa 论文/上游 | 本项目 |
|---|---|---|
| 短 RPC P99 vs TCP | **快 19-72×**（数据中心交换网，80% 负载 P99<15µs） | loopback 混合负载下 P99 快 ~2×（见 benchmark 输出；loopback 无网卡优先级队列，不声称复现论文数字） |
| IANA 协议号 | **146**（HOMA） | 用户态 UDP 承载，未用协议号 |
| 上游状态 | Linux 内核补丁 **v16** 轮（2024-11，仍在 review） | 纯用户态，免内核补丁 |

本地 benchmark 实测（release，loopback，500×100B 短 + 50×1MB 长，8 线程）：

| 实现 | 短P50 | 短P90 | 短P99 | 长P50 | 长P90 | 长P99 |
|---|---|---|---|---|---|---|
| homa-rpc | 862 µs | 1363 µs | 4284 µs | 38.2 ms | 51.0 ms | 234.2 ms |
| tcp-baseline（短连接） | 1447 µs | 1943 µs | 3145 µs | 2.9 ms | 3.9 ms | 15.9 ms |

短 RPC P50 快 ~1.7×；单条 1MB RPC 从初版 73ms 优化到 ~10ms（授权节流 + 大缓冲 + overcommit），
但高并发下长消息仍明显慢于 TCP（见 TODO）。loopback 无网卡优先级队列，不声称复现论文数字。

## 已知 TODO / 技术债

- **长消息高并发吞吐仍是最大短板**：单 IO 线程 + 授权自时钟的调度延迟叠加，
  8 线程 1MB 混合负载下长 RPC P50 38ms vs TCP 2.9ms。方向：真正的 pacing（定时器轮/批量授权）、
  多 IO 线程、io_uring/AF_XDP 旁路。
- 8 级 QoS 队列已实现发送侧插队（txqueue.rs，有单测），但 loopback 上无网卡队列，效果仅限本机调度顺序。
- overcommit（默认 K=2）+ starve_threshold 强制授权已防饿死；K 的网络侧最优值未调。
- BUSY 仅定义与处理，默认阈值极大不触发。
- linger/去重缓存均为内存驻留，无持久化与容量回收策略。
