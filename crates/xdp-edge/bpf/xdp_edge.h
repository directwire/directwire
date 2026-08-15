/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xdp_edge.h —— 数据面与控制面共享的 ABI 定义。
 * Rust 模拟器（src/）中的结构与这里的字段一一对应。
 */

#ifndef XDP_EDGE_H
#define XDP_EDGE_H

#define MAX_BACKENDS     256
#define MAGLEV_LUT_SIZE  65537          /* 大质数，与 Katran 默认一致 */
#define CONNTRACK_SIZE   (1 << 20)      /* 100 万连接 */
#define RATELIMIT_SIZE   (1 << 20)
#define SYN_TRACK_SIZE   (1 << 16)

/* 令牌桶定点数：1 个令牌 = 1<<16（16.16 定点，BPF 内无浮点） */
#define TOK_ONE          (1ULL << 16)

/* 后端信息 */
struct backend_info {
    __u32 ip;          /* 后端内网 IP（IPIP 外层目的地） */
    __u8  dmac[6];     /* 后端/下一跳 MAC，由控制面 ARP 解析后写入；全 0 = 未解析 */
    __u16 flags;       /* 保留：权重 / 健康状态 */
};

/* 五元组（连接跟踪键）。端口保留网络字节序，哈希前无需转换。 */
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
};

/* 连接表项值：存后端索引而非 IP —— 转发路径需回查 backends map 取
 * dmac 做以太网头重写；IP 可通过 backends[backend_idx].ip 派生。
 * Rust 模拟器侧 ConnEntry 存的是决策结果（backend_ip），语义等价。 */
struct conn_value {
    __u32 backend_idx;
    __u64 last_seen_ns;
};

/* 令牌桶（定点令牌计数） */
struct token_bucket {
    __u64 tokens;      /* 16.16 定点 */
    __u64 last_ns;
};

/* 限速 map 占用状态（单槽 ARRAY，数据面 __sync_fetch_and_add 更新） */
struct rl_state {
    __u64 occupancy;   /* 累计插入过的源数；> RATELIMIT_SIZE 表示已发生 LRU 淘汰 */
};

/* SYN 滑动窗口 */
struct syn_window {
    __u32 syn;
    __u32 ack;
    __u64 start_ns;
};

/* 全局配置（控制面写入） */
struct edge_config {
    __u64 rate_per_ns_fp;   /* 限速速率，令牌/纳秒，16.16 定点 */
    __u64 rate_burst;       /* 突发容量（定点） */
    __u64 syn_window_ns;    /* SYN 检测窗口 */
    __u32 syn_threshold;    /* 窗口内触发判定的最小 SYN 数 */
    __u32 syn_ack_ratio;    /* SYN/ACK 比率阈值 */
    __u32 gateway_ip;       /* IPIP 外层源地址（网关内网 IP） */
    __u8  gateway_smac[6];  /* 网关本机 MAC（XDP_TX 回注时作 h_source） */
    __u8  pad[2];
};

/* stats map 下标 */
enum stat_idx {
    ST_FORWARD = 0,
    ST_DROP_RATE,
    ST_DROP_SYN,
    ST_CONN_HIT,
    ST_CONN_MISS,
    ST_DROP_NOMAC,    /* 后端 MAC 未解析（控制面未写入 dmac） */
    ST_RL_EVICT,      /* 限速 map 满触发 LRU 淘汰 */
    ST_MAX,
};

#endif /* XDP_EDGE_H */
