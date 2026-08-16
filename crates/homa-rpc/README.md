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

        RpcServer: recv 循环 ──> 幂等去重缓存 ──> 固定工作池(32) ──> 回响应
```

关键工程决策：两个核心状态机**不碰 socket**，输入包、输出 `Action` 列表（Send/Deliver），因此调度器、重组、重传全部可以脱离网络做确定性单测。

## 快速开始

```bash
cargo test                              # 29 个测试：SRPT/重组/重传/RPC 端到端
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
| 短 RPC vs TCP | **快 19-72×**（数据中心交换网，80% 负载 P99<15µs） | loopback 混合负载下 P50 快 2.7×、P99 快 1.2×（见下方实测；loopback 无网卡优先级队列，不声称复现论文数字） |
| IANA 协议号 | **146**（HOMA） | 用户态 UDP 承载，未用协议号 |
| 上游状态 | Linux 内核补丁 **v16** 轮（2024-11，仍在 review） | 纯用户态，免内核补丁 |

本地 benchmark 实测（release，loopback，500×100B 短 + 50×1MB 长，8 线程，`HOMA_LONG_EVERY=11`）：

| 实现 | 短P50 | 短P90 | 短P99 | 长P50 | 长P90 | 长P99 | 总墙钟 |
|---|---|---|---|---|---|---|---|
| homa-rpc | 520 µs | 964 µs | 1569 µs | 4.62 ms | 5.93 ms | 7.51 ms | **66.4 ms** |
| tcp-baseline（短连接） | 1407 µs | 1781 µs | 1934 µs | 2.71 ms | 3.22 ms | 3.49 ms | 94.3 ms |

短 RPC P50 快 **2.7×**（P90 1.85×、P99 1.23×，全档位都赢）；长 RPC 为 SRPT 调度让位付协议税
（~1.7× 慢，单条 1MB RPC 已从初版 73ms → 攻坚前 38ms → 现 4.6ms，约 16×）；总墙钟 550 次
混合负载 homa 快于 TCP **30%**。长消息的差距是结构性协议成本（首 RTT 授权往返 + 让位短消息），
正是短消息全档位碾压的代价——loopback 无网卡优先级队列，不声称复现论文数字。

## 已知 TODO / 技术债

- **长消息剩余差距为结构性协议税**（授权往返 + SRPT 让位）。实测
  （2026-08-16，`mix_probe` + `debug_stats`，550 混合负载含 50×1MiB）：
  io_loop **锁内泵送不是争用点**——`io_lock_avg_batch` 16.9µs（持锁）、
  `io_lock_wait_batch` 0.6µs（等锁）、`io_lock_per_pkt` 0.92µs，收包线程从不等锁。
  旧注「把分片构建移出收包线程」的机制**被实测否定**；~170µs/方向的真实来源是
  每分片 `Packet::encode` 的一次 Vec 分配 + 负载 memcpy（≈250ns × 874 ≈ 200µs/1MiB
  方向）。若做真正的零拷贝 sendmsg（header iovec + 负载切片，内核聚集，免 Rust 侧
  拼包拷贝）可省这笔——但那是 ~20% 收益、改核心传输路径，随多机测试床一起待办，
  不在单机 loopback 上冒险。
- 8 级 QoS 队列已实现发送侧插队（txqueue.rs，有单测），但 loopback 上无网卡队列，效果仅限本机调度顺序。
- overcommit（默认 K=2）+ starve_threshold 强制授权已防饿死；K 的网络侧最优值未调。
- BUSY 仅定义与处理，默认阈值极大不触发。
- linger/去重缓存均为内存驻留，无持久化与容量回收策略。
