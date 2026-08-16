// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_edge.c —— 边缘网关 XDP 数据面（形态一，Linux 构建）
 *
 * 功能：
 *   1. 四层负载均衡：Maglev 一致性哈希选后端 + IPIP 封装 XDP_TX 转发
 *   2. 连接跟踪：LRU hash map，命中即复用既有后端决策（连接亲和）
 *   3. DDoS 防护：per-源 IP 令牌桶限速 + SYN flood 检测，XDP_DROP 快速路径
 *
 * 用户态对应物：src/ 下的 Rust 模拟器逐包复刻本程序语义，
 * 便于在无 eBPF 工具链的开发机上验证架构。
 *
 * 构建：见 bpf/Makefile（clang -target bpf）
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_edge.h"

/* ---------------- BPF Maps ---------------- */

/* 后端表：索引 -> 后端内网 IP（IPIP 外层目的地） */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, struct backend_info);
} backends SEC(".maps");

/* Maglev 查找表：槽位 -> 后端索引。由控制面（Go/Rust agent）在用户态
 * 填充（复刻 Google Maglev 置换算法），数据面只做一次取模查表。 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAGLEV_LUT_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} maglev_lut SEC(".maps");

/* 连接跟踪：五元组 -> 选路决策。LRU 淘汰由内核保证。 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CONNTRACK_SIZE);
    __type(key, struct flow_key);
    __type(value, struct conn_value);
} conntrack SEC(".maps");

/* per-源令牌桶限速 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATELIMIT_SIZE);
    __type(key, __u32);               /* 源 IP */
    __type(value, struct token_bucket);
} ratelimit SEC(".maps");

/* 限速 map 占用计数（单槽 ARRAY）：数据面原子累加插入过的源数，
 * 用于判定 LRU 淘汰发生（见 xdp_edge_main 限速段注释） */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rl_state);
} rl_state SEC(".maps");

/* per-源 SYN/ACK 滑动窗口计数（SYN flood 检测） */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SYN_TRACK_SIZE);
    __type(key, __u32);               /* 源 IP */
    __type(value, struct syn_window);
} syn_track SEC(".maps");

/* 全局配置（限速速率、阈值等），控制面在加载后写入 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct edge_config);
} config SEC(".maps");

/* 决策统计（per-CPU，无锁） */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ST_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* ---------------- 内联辅助 ---------------- */

static __always_inline void bump_stat(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&stats, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

/* 五元组哈希（jhash 语义简化：两级混合），与 Rust 侧 flow_hash 对应 */
static __always_inline __u32 flow_hash(const struct flow_key *k)
{
    __u64 h = (__u64)k->src_ip << 32 | k->dst_ip;
    h *= 0x100000001b3ULL;
    h ^= ((__u64)k->src_port << 16) | k->dst_port;
    h ^= (__u64)k->protocol << 48;
    h ^= h >> 30; h *= 0xbf58476d1ce4e5b9ULL;
    h ^= h >> 27; h *= 0x94d049bb133111ebULL;
    h ^= h >> 31;
    return (__u32)h;
}

/* 令牌桶：纳秒时钟补充，token>=1 才放行 */
static __always_inline int rate_allow(struct token_bucket *tb,
                                      __u64 now_ns, __u64 rate_per_ns_fp,
                                      __u64 burst)
{
    __u64 elapsed = now_ns - tb->last_ns;
    if ((__s64)elapsed > 0) {
        /* 定点数（16.16）避免浮点：tokens += elapsed * rate */
        tb->tokens += (elapsed * rate_per_ns_fp) >> 16;
        if (tb->tokens > burst)
            tb->tokens = burst;
        tb->last_ns = now_ns;
    }
    if (tb->tokens >= TOK_ONE) {
        tb->tokens -= TOK_ONE;
        return 1;
    }
    return 0;
}

/* SYN flood 窗口判定：窗口内 SYN 超阈值且 SYN > ACK * 比率 */
static __always_inline int syn_is_flood(struct syn_window *w, __u64 now_ns,
                                        __u8 is_syn, __u8 is_ack,
                                        const struct edge_config *cfg)
{
    if (now_ns - w->start_ns >= cfg->syn_window_ns) {
        w->syn = 0;
        w->ack = 0;
        w->start_ns = now_ns;
    }
    if (is_syn)
        w->syn++;
    else if (is_ack)
        w->ack++;
    return w->syn >= cfg->syn_threshold && w->syn > w->ack * cfg->syn_ack_ratio;
}

/* IP 头校验和（RFC 1071）。外层头 20B = 10 个 16 位字；逐字节取
 * (hi<<8)|lo 即网络序字面值，故计算与主机字节序无关。所有循环都是常量
 * 边界，验证器直接放行。刻意不用 bpf_csum_diff——该 helper 不在 XDP 的
 * 可用函数列表里（仅在 SOCKET_FILTER/SCHED_CLS 等类型可用）。 */
static __always_inline __sum16 ip_checksum(const void *data)
{
    const __u8 *b = (const __u8 *)data;
    __u64 sum = 0;
#pragma unroll
    for (__u32 i = 0; i < sizeof(struct iphdr) / 2; i++)
        sum += (b[i * 2] << 8) | b[i * 2 + 1];
    /* 10 字累加和 < 2^20，折两次必收敛到 16 位（无数据相关循环） */
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__sum16)~sum;
}

/*
 * IPIP 封装：包头前推一个外层 IPv4 头，重写以太网头后 XDP_TX 从原网卡发出。
 *
 * MAC 处理数据流（明确委托控制面）：
 *   控制面 agent 负责邻居解析——对每个后端 IP 周期性 ARP/NDP 解析，
 *   把结果写入 backends map 的 backend_info.dmac；网关本机 MAC 与内网 IP
 *   写入 config.gateway_smac / gateway_ip。数据面只做字段拷贝，
 *   不在 XDP 内做邻居发现（XDP 无法睡眠、无 ARP 协议栈）。
 *   dmac 为全 0 视为未解析：直接 XDP_DROP 并计数，避免把坏帧发上链路。
 */
static __always_inline int ipip_encap_tx(struct xdp_md *ctx,
                                         const struct backend_info *be,
                                         const struct edge_config *cfg)
{
    /* 前推 sizeof(struct iphdr)：原 [eth][ip]... 变为 [eth][outer_ip][inner_ip]... */
    if (bpf_xdp_adjust_head(ctx, (int)(0 - (int)sizeof(struct iphdr))))
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *outer = (void *)(eth + 1);
    struct iphdr *inner = (void *)(outer + 1);
    if ((void *)(inner + 1) > data_end)
        return XDP_DROP;

    /* adjust_head 后以太网头已由内核平移到新 data 起点（内容不变），
     * 但目的 MAC 仍是上游交换机/路由器的，必须重写为后端 MAC：
     * h_dest = 后端 dmac（控制面解析），h_source = 网关本机 MAC。 */
    if (be->dmac[0] == 0 && be->dmac[1] == 0 && be->dmac[2] == 0 &&
        be->dmac[3] == 0 && be->dmac[4] == 0 && be->dmac[5] == 0) {
        bump_stat(ST_DROP_NOMAC);
        return XDP_DROP;
    }
    __builtin_memcpy(eth->h_dest, be->dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, cfg->gateway_smac, ETH_ALEN);
    /* eth->h_proto 保持 ETH_P_IP 不变 */

    /* 复制内层头字段构造外层头 */
    __u8 tos = inner->tos;
    __u16 tot_len = bpf_htons(bpf_ntohs(inner->tot_len) + sizeof(struct iphdr));

    outer->version = 4;
    outer->ihl = 5;
    outer->tos = tos;
    outer->tot_len = tot_len;
    outer->id = 0;
    outer->frag_off = bpf_htons(IP_DF);
    outer->ttl = 64;
    outer->protocol = IPPROTO_IPIP;
    outer->saddr = cfg->gateway_ip;   /* 网关内网 IP，控制面写入 */
    outer->daddr = be->ip;
    outer->check = 0;
    /* 外层头校验和：清零后手算（RFC 1071，XDP 内无 bpf_csum_diff） */
    outer->check = ip_checksum(outer);
    return XDP_TX;
}

/* ---------------- XDP 主程序 ---------------- */

SEC("xdp")
int xdp_edge_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 cfg_key = 0;
    struct edge_config *cfg = bpf_map_lookup_elem(&config, &cfg_key);
    if (!cfg)
        return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();

    /* ---- 1. per-源令牌桶限速 ----
     *
     * map 满的淘汰语义：ratelimit 是 BPF_MAP_TYPE_LRU_HASH，
     * 内核在 map 满时对 bpf_map_update_elem 自动淘汰最久未活跃源
     * 腾出槽位（update 不会因满而失败），新源因此总能被限速覆盖。
     * 为观测淘汰压力，用 rl_state.occupancy 原子计数累计插入过的源数：
     * occupancy > RATELIMIT_SIZE 即说明已经发生 occupancy - SIZE 次
     * LRU 淘汰，此时 bump ST_RL_EVICT 供控制面告警/评估扩容。
     * 防御性保留失败分支：万一 update 仍失败（内存压力下），
     * 放行本包但不建立桶——宁可漏限速也不误伤正常业务。 */
    struct token_bucket *tb = bpf_map_lookup_elem(&ratelimit, &ip->saddr);
    if (!tb) {
        struct token_bucket init = { .tokens = cfg->rate_burst, .last_ns = now };
        if (bpf_map_update_elem(&ratelimit, &ip->saddr, &init, BPF_ANY) == 0) {
            __u32 st_key = 0;
            struct rl_state *rs = bpf_map_lookup_elem(&rl_state, &st_key);
            if (rs) {
                __u64 occ = __sync_fetch_and_add(&rs->occupancy, 1) + 1;
                if (occ > RATELIMIT_SIZE)
                    bump_stat(ST_RL_EVICT);
            }
            tb = bpf_map_lookup_elem(&ratelimit, &ip->saddr);
        }
    }
    if (tb && !rate_allow(tb, now, cfg->rate_per_ns_fp, cfg->rate_burst)) {
        bump_stat(ST_DROP_RATE);
        return XDP_DROP;
    }

    /* ---- 解析四层头，构造五元组 ---- */
    struct flow_key fk = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .protocol = ip->protocol,
    };
    __u8 is_syn = 0, is_ack = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;
        fk.src_port = tcp->source;
        fk.dst_port = tcp->dest;
        is_syn = tcp->syn && !tcp->ack;
        is_ack = tcp->ack;

        /* ---- 2. SYN flood 检测 ---- */
        struct syn_window *w = bpf_map_lookup_elem(&syn_track, &ip->saddr);
        if (!w) {
            struct syn_window init = { .start_ns = now };
            bpf_map_update_elem(&syn_track, &ip->saddr, &init, BPF_ANY);
            w = bpf_map_lookup_elem(&syn_track, &ip->saddr);
        }
        if (w && syn_is_flood(w, now, is_syn, is_ack, cfg)) {
            bump_stat(ST_DROP_SYN);
            return XDP_DROP;
        }
    } else {
        struct udphdr *udp = (void *)ip + ip->ihl * 4;
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;
        fk.src_port = udp->source;
        fk.dst_port = udp->dest;
    }

    /* ---- 3. 连接跟踪：命中复用决策，保证连接亲和 ---- */
    struct conn_value *cv = bpf_map_lookup_elem(&conntrack, &fk);
    struct backend_info *be;
    if (cv) {
        bump_stat(ST_CONN_HIT);
        cv->last_seen_ns = now;
        /* conn_value 存后端索引：转发必须回查 backends 取 dmac 重写 MAC */
        be = bpf_map_lookup_elem(&backends, &cv->backend_idx);
        if (!be)
            return XDP_PASS;
    } else {
        /* ---- 4. Maglev 选后端 ---- */
        bump_stat(ST_CONN_MISS);
        __u32 slot = flow_hash(&fk) % MAGLEV_LUT_SIZE;
        __u32 *bidx = bpf_map_lookup_elem(&maglev_lut, &slot);
        if (!bidx)
            return XDP_PASS;
        be = bpf_map_lookup_elem(&backends, bidx);
        if (!be)
            return XDP_PASS;

        struct conn_value nv = { .backend_idx = *bidx, .last_seen_ns = now };
        bpf_map_update_elem(&conntrack, &fk, &nv, BPF_ANY);
    }

    /* ---- 5. IPIP 封装 + XDP_TX ---- */
    bump_stat(ST_FORWARD);
    return ipip_encap_tx(ctx, be, cfg);
}

char _license[] SEC("license") = "GPL";
