# ROADMAP — homa-rpc 12 个月路线图

| 阶段 | 时间 | 里程碑 | 人力估算 |
|---|---|---|---|
| **MVP**（已完成） | Q1 | 用户态 Homa-lite over UDP：消息导向、未调度窗口、GRANT/SRPT（overcommit+防饿死+授权节流）、乱序重组、RESEND 重传、发送侧 8 级 QoS 队列、at-least-once RPC、loopback benchmark vs TCP（500短+50长×1MB）、25 项测试全绿 | 1 人 × 1 月 |
| **Alpha** | Q2 | 长消息高并发吞吐攻坚（真 pacing/定时器轮、多 IO 线程——当前 8 线程下长 RPC P50 38ms vs TCP 2.9ms）；真实双机 RDMA-less 万兆网 benchmark；丢包/乱序故障注入测试；CI 与模糊测试 | 2 人 × 3 月 |
| **Beta** | Q3 | 生产化：连接级流控与内存水位、指标/ tracing、配置化、与 gRPC 语义对齐的 IDL 层（或对接 tonic 传输层）；灰度集群试点（≥50 节点），输出 P50/P99 对比报告 | 3 人 × 3 月 |
| **商用化** | Q4 | 云上托管版与 SLA；内核旁路优化（AF_XDP/io_uring 或协议号 146 原生承载评估）； upstream 社区互动（跟踪内核 v16+ 补丁）；大客户 POC 与商务闭环 | 4 人 × 3 月（含 1 商务/1 SRE） |

每季度出口标准：Q2 真实网络下短 RPC P99 ≥ 5× TCP；Q3 灰度集群 7 天无 P1 事故；Q4 至少 1 个付费 POC。
