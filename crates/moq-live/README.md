# moq-live —— MoQ 国产化低延迟直播传输（架构验证骨架）

> Rust + quinn 实现的 MoQ-lite MVP：发布/订阅模型的低延迟直播传输，
> 中继即缓存、可感知优先级做丢包决策，loopback 上演示 1 publisher → relay → 3 subscriber。

## 项目定位与降维逻辑

**MoQ（Media over QUIC，IETF draft-ietf-moq-transport-17）是下一代直播/实时媒体标准。**
它把直播从「文件分片拉取」（HLS/LL-HLS）降维成「对象流订阅」：

| 维度 | LL-HLS / RTMP 系 | MoQ（本项目对标的范式） |
|---|---|---|
| 传输单元 | 分片文件（part/segment） | object（一帧/一切片，可独立丢弃） |
| 中继角色 | 透明缓存（HTTP 语义） | **可感知 group/priority 的智能缓存**，拥塞时主动丢低优先级 object |
| 订阅语义 | 轮询拉取 | publish/subscribe，迟到者从**最新 group 开头**追赶 |
| 端到端延迟 | 2-5s（LL-HLS） | **0.3-1s** |
| 连接复用 | TCP/H2 队头阻塞 | QUIC 多流，无队头阻塞 |

**国产替代窗口**：Cloudflare 已把 MoQ 跑上 330+ 城市的生产中继网，NAB 2026 展示了
11 家厂商互联互通；而国内声网/即构等全部是私有 UDP 协议、对 IETF 标准进程零参与。
这是 2-3 年的标准卡位窗口——谁先做出合规的中继与 SDK，谁就能吃到国产化替代的红利。

**本仓库是「可运行的架构验证骨架」**：协议细节做了简化（见技术债），但核心范式全部
真实实现并有测试覆盖——varint 帧编解码、namespace/track/group/object 寻址、按 group
的中继缓存、追赶语义、优先级感知的丢帧决策、loopback 上的真实 QUIC 扇出。

## 架构

```
                 ┌────────────────────────── moq-live ──────────────────────────┐
                 │                                                              │
  Publisher      │                    Relay (src/relay.rs)                      │     Subscriber A/B/C
  (examples/     │   ┌──────────────────────────────────────────────┐           │     (examples/live_demo.rs)
   live_demo.rs) │   │  Hub (src/hub.rs) 扇出枢纽                    │           │
       │         │   │  ┌────────────────────────────────────────┐  │           │
       │ 控制流   │   │  │ track: live/camera-01/video            │  │           │
       │ SETUP───┼──►│  │  ┌─────────────┐   ┌────────────────┐  │  │           │
       │ ANNOUNCE│   │  │  │ GroupCache   │   │ broadcast 扇出  │  │  │           │
       │         │   │  │  │ 最近 N group │──►│ tx ──┬──┬──┬──  │  │  │           │
       │ 数据流   │   │  │  │ (追赶窗口)   │   │      │  │  │     │  │  │           │
       │ uni/g───┼──►│  │  └─────────────┘   └──────┼──┼──┼────┘  │  │           │
       │ (每group│   │  └───────────────────────────┼──┼──┼───────┘  │           │
       │ 一条流) │   └──────────────────────────────┼──┼──┼──────────┘           │
       │         │                                  │  │  │                      │
       │         │        ① SUBSCRIBE 时回放缓存快照  │  │  │  ② 之后实时转发       │
       │         │        （最新 group 开头切入）◄────┘  │  │   （每 group 一条新流）│
       │         │        ③ 下行经 PriorityDropQueue：拥塞时驱逐低优先级非关键帧；    │
       │         │           broadcast Lagged ──► 丢 P 帧直到下一个 I 帧（group 头）  │
       │         │                                  └──┴──┴──► group 单向流 ──────┼───► 延迟统计
       │         │        ④ 首个订阅触发 relay 向上游转发 SUBSCRIBE，协商 track alias │
       │         │           （publisher 后续 group 流头用 alias 代替完整 track）     │
       │         │        ⑤ GOAWAY 优雅关闭 / UNSUBSCRIBE 即停 / SUBSCRIBE_ERROR      │
                 └──────────────────────────────────────────────────────────────────┘

  消息层（src/message.rs）：varint(type) + varint(len) + payload
  控制流（每连接一条双向流）：
  ├─ SETUP          版本 + 角色（Publisher/Subscriber/Both）协商
  ├─ ANNOUNCE       声明 namespace ──► ANNOUNCE_OK
  ├─ SUBSCRIBE      subscribe_id + track_alias + track + 起始模式 + 优先级
  │                 ──► SUBSCRIBE_OK / SUBSCRIBE_ERROR（命名空间未发布等）
  ├─ UNSUBSCRIBE    取消订阅，relay 立即停止转发
  └─ GOAWAY         优雅关闭通告（relay shutdown 时广播）
  数据流（stream-per-group，每 group 一条独立单向流）：
  ├─ GROUP_HEADER   TrackRef（Alias / Full 回退）+ group_id（流首帧）
  └─ OBJECT × N     object_id + priority + timestamp + payload（group_id 由流头携带）
```

## 快速开始

```bash
# 1. 跑演示：1 publisher（25fps 模拟视频帧）→ relay → 3 subscriber（C 迟到 1.5s，演示追赶）
cargo run --example live_demo

# 2. 跑测试：帧编解码往返 / 缓存逻辑 / 扇出逻辑 / loopback 端到端
cargo test
```

演示实际输出（Windows loopback，75 帧 × 16 KB × 3 订阅端；alias 协商与 GOAWAY 可见）：

```
publisher: group 0 推完（帧头: full track）
[relay] 上游 alias 协商: live/camera-01/video -> alias=1
publisher: group 2 推完（帧头: alias）
subscriber A: 收到 75 帧，首帧 group = Some(0)
subscriber B: 收到 75 帧，首帧 group = Some(0)
subscriber C: 收到 50 帧，首帧 group = Some(1)（迟到加入 → 从最新 group 开头追赶切入）
  总体: n=200 min=0ms avg=1ms p95=2ms max=35ms
== relay 发送 GOAWAY 优雅关闭 ==
```

> loopback 延迟仅验证管线正确性；真实公网延迟目标对标 MoQ 的 0.3-1s。

## 对标数据

| 指标 | 行业现状 | 来源 |
|---|---|---|
| Cloudflare MoQ 生产中继覆盖 | **330+ 城市** | Cloudflare 公开披露（2025-2026） |
| NAB 2026 MoQ 互联互通 | **11 家厂商**互操作演示 | NAB 2026 展会 |
| MoQ 端到端延迟 | **0.3-1s** | IETF draft / 厂商实测 |
| LL-HLS 端到端延迟 | 2-5s | 行业公认区间 |
| 国内厂商参与度 | 声网/即构等均为私有 UDP 协议，**零参与 IETF MoQ** | 公开资料 |

## 国密+后量子会话层（feature `gm-pq`）

在 QUIC TLS 之上叠加来自隔壁 **gm-pq-stack** 的「SM2-ECDH + ML-KEM-768」混合握手会话层（SM4-GCM 传输加密），面向国内关基/政企合规场景：传输层 QUIC 保证互通，会话层国密+PQ 保证抗量子与商用密码合规。

```bash
cargo run --example gmpq_demo --features gm-pq   # 完整握手 + 0-RTT 恢复 + GOAWAY 全链路演示
cargo test --features gm-pq                       # 39 个测试（默认 36 + GM 集成 3）
```

- 契约：QUIC 连接建立后第一条双向流上完成混合握手，通过后才允许 SETUP/ANNOUNCE/SUBSCRIBE。
- 阻塞 gm-pq API ↔ tokio 异步：工作线程 + 共享桥（Mutex/Condvar + Notify）适配，见 `src/gmpq.rs`。
- 信任锚：示例用内存 `PinFileAnchor::from_keys` 钉扎对端 SM2 公钥；生产换 `PinFileAnchor::from_file`。
- 支持 0-RTT 票据恢复（`client_connect_resume`），demo 实测重连 `early_data_accepted=true`。
- 三条红线（继承自 gm-pq-stack INTEGRATION.md）：client_tag 绑定来源身份；0-RTT 数据必须幂等（demo 用幂等探针）；TicketCache 跨连接共享。

demo 实测（debug 构建，SM2 纯软件实现）：完整握手 ~73ms；0-RTT 恢复 ~74ms；75 帧端到端 avg 0ms / p95 1ms。

## 代码结构

```
src/
├── varint.rs   QUIC varint（RFC 9000 §16）编解码
├── message.rs  控制面全消息（SETUP/ANNOUNCE(+OK)/SUBSCRIBE(+OK/ERROR)/UNSUBSCRIBE/GOAWAY）
│               + 数据面 GROUP_HEADER（TrackRef: Alias/Full）/OBJECT 帧
├── track.rs    TrackId / Object / Priority 抽象（0 为最高优先级）
├── cache.rs    GroupCache：最近 N 个 group 的滑动窗口 + 追赶快照
├── hub.rs      Hub：命名空间注册表 + 缓存 + broadcast 扇出
├── dropq.rs    PriorityDropQueue：拥塞时按优先级驱逐非关键帧（group 头受保护）
├── net.rs      QUIC endpoint + 证书钉扎 verifier + FrameReader 流式帧读取
├── relay.rs    中继：控制面分发 + stream-per-group 数据面解复用/再始发起流
│               + 上游 alias 协商 + GOAWAY 优雅关闭
└── client.rs   Publisher（begin_group/GroupWriter）/ Subscriber（订阅路由/事件）API
tests/
├── codec.rs    varint 边界 + 全消息类型往返 + alias 压缩验证 + 畸形帧拒绝（14 项）
├── cache.rs    窗口淘汰 / 乱序插入 / 晚到丢弃 / 快照语义（6 项）
├── dropq.rs    丢弃队列：容量 / 驱逐策略 / group 头保护（6 项）
├── fanout.rs   多订阅者扇出 / 迟到回放 / Lagged 行为（5 项）
├── control.rs  SUBSCRIBE_ERROR / UNSUBSCRIBE / GOAWAY（3 项，loopback）
├── tls.rs      证书钉扎：正确可通过 / 错误必须在握手失败（1 项）
└── loopback.rs 真实 QUIC 端到端：收齐 + 追赶 + alias 协商生效（1 项）
examples/
└── live_demo.rs 1 pub → relay → 3 sub 实时帧流 + 延迟统计 + GOAWAY 关闭演示
```

## 已知技术债（TODO）

1. ~~**对象流传输**~~：✅ 已完成 stream-per-group（每 group 一条独立单向流，
   GROUP_HEADER + OBJECT 序列）；剩余：QUIC datagram 支持（音频等可丢轨道）。
2. ~~**TLS 校验**~~：✅ 已改为证书公钥钉扎（`PinnedServerCert`，demo/测试均钉扎）；
   剩余：生产接平台根证书（rustls-platform-verifier）+ 有效期/SAN 校验。
3. **优先级调度**：✅ 已实现 PriorityDropQueue（下行拥塞按优先级驱逐非关键帧）+
   Lagged 丢 P 保 I；剩余：与 QUIC 拥塞窗口联动的主动背压。
4. ~~**track alias**~~：✅ 已完成（SUBSCRIBE 携带订阅方 alias；relay 向上游转发
   SUBSCRIBE 分配 alias；group 流头用 alias，协商前回退 Full）。
5. **订阅状态机**：✅ 已补 UNSUBSCRIBE / SUBSCRIBE_ERROR / ANNOUNCE_OK / GOAWAY；
   剩余：SUBSCRIBE_UPDATE、ANNOUNCE 撤销、订阅超时等完整生命周期。
6. **去重**：replay 与 live 依赖同一把写锁保证无重叠无空隙，跨 relay 级联时需显式
   (group, object) 去重。
7. **多 publisher/多 track 拓扑**：alias 协商按「单 publisher 单 track」假设实现，
   级联 relay 与多发布者场景需完善上游注册表。
