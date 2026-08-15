# ROADMAP —— moq-live 12 个月路线图

总目标：从「可运行的架构验证骨架」到「可商用的国产化 MoQ 直播传输栈」，
对齐 draft-ietf-moq-transport（-17 及后续），抢占国内 2-3 年标准窗口。

---

## Q1（M1-M3）：MVP 架构验证 ✅（本仓库交付物）

**目标**：跑通核心范式，证明 Rust + quinn 技术栈可行。

| 里程碑 | 内容 | 状态 |
|---|---|---|
| M1.1 | varint 帧编解码 + 核心消息（SETUP/ANNOUNCE/SUBSCRIBE/OBJECT） | ✅ 14 项编解码测试 |
| M1.2 | Track 抽象 + 按 group 滑动窗口缓存 | ✅ 6 项测试 |
| M1.3 | relay 扇出 + 追赶语义 + Lagged 丢帧 | ✅ 5 项测试 |
| M1.4 | loopback 端到端演示（1 pub → 3 sub，延迟统计） | ✅ |
| M1.5 | **完善轮**：stream-per-group 数据面、track alias 压缩、控制面补全（UNSUBSCRIBE/SUBSCRIBE_ERROR/ANNOUNCE_OK/GOAWAY）、证书钉扎、优先级丢弃队列 | ✅ 36 项测试全绿 |

**人力**：1 名资深协议工程师 × 1 个月（实际含完善轮约 1.2 个月）。

---

## Q2（M4-M6）：alpha —— 协议对齐与真实媒体

**目标**：从私有 MoQ-lite 帧格式切换到 draft-17 兼容 wire format，接入真实编解码。

- M4：消息层对齐 draft-17（完整 SUBSCRIBE 状态机：SUBSCRIBE_UPDATE/超时；
  ANNOUNCE 撤销；alias 生命周期管理）。~~OBJECT stream-per-group~~ 已在 Q1 完成，
  M4 追加 QUIC datagram 支持（音频等可丢轨道）。
- M5：接入真实视频源（H.264  annexb → group=GOP/object=NALU 切片）；
  publisher SDK 雏形（推送 OBS/FFmpeg 输出）。
- M6：优先级分级丢弃队列 + 基于 QUIC 拥塞窗口的背压；relay 级联（两级中继）。
- 验收：与至少一个开源 MoQ 实现（moq-rs / moq-transport）互操作 ping-pong；
  1080p30 真实码流 loopback 端到端 < 100ms。

**人力**：2 名协议工程师 + 1 名流媒体工程师 × 3 个月。

---

## Q3（M7-M9）：beta —— 生产化与互操作

**目标**：达到生产可用性门槛，参与公开互操作。

- M7：TLS 平台证书校验（~~证书钉扎~~已在 Q1 完成，M7 接 rustls-platform-verifier
  与有效期/SAN 校验）、token 鉴权、namespace 权限模型；relay 配置化与可观测
  （Prometheus 指标：扇出订阅数、缓存命中率、丢帧率、E2E 延迟直方图）。
- M8：公网压测（单 relay 1 万订阅扇出、弱网丢包 5% 下追赶行为）；QUIC datagram
  支持（音频低优先级轨道）。
- M9：参加 MoQ 社区 interop 测试；subscriber SDK（Web 端经 WebTransport 网关、
  移动端 Rust 核心 + Kotlin/Swift 绑定）。
- 验收：3 城市 relay 组网实测 E2E 延迟 0.3-1s；interop 通过 draft-17 核心用例。

**人力**：3 名工程师 + 1 名 SRE × 3 个月；云资源预算约 5 万/月。

---

## Q4（M10-M12）：商用化

**目标**：首个商业客户上线，形成国产替代叙事。

- M10：SLA 加固（relay 多活、会话迁移、零停机升级）；运维控制台。
- M11：标杆客户 POC（赛事/电商直播场景，10 万级并发订阅验证）；
  与国产编解码（AVS3）适配。
- M12：商业化发布：relay 私有化部署包 + SDK 授权模式；
  向 IETF/CCSA 提交标准化提案，建立话语权。
- 验收：至少 1 个付费客户生产上线；E2E 延迟 ≤1s @ 99 分位；系统可用性 99.9%。

**人力**：5 名工程师 + 1 名产品/售前 × 3 个月。

---

## 风险与依赖

| 风险 | 缓解 |
|---|---|
| IETF draft 仍在演进，wire format 可能 breaking | 版本协商层预留；跟踪 draft 双周同步 |
| quinn/rustls 上游变更 | 锁定 minor 版本，CI 跑兼容矩阵 |
| 国内云厂商 QUIC 支持参差（UDP 限速/QoS） | 弱网测试前置到 Q3；备 TCP fallback 方案（仅信令） |
| 人才稀缺（Rust + 流媒体 + 协议） | Q1 起建立内部 MoQ 知识库，与社区共建 |
