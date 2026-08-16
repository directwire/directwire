#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""xdp-edge 内核数据面 CI 实测。

在 GitHub Actions ubuntu runner（有 sudo、真内核）上：
  1. 建 veth 对，挂 xdp_edge.o 到 veth0 的 XDP 钩子（验证器通过 = 加载成功）；
  2. 预填 config / backends / conntrack map，从 veth1 注入一个自制 TCP SYN；
  3. 断言 veth1 收到 IPIP 封装后 XDP_TX 回来的包（外层 proto=4、saddr=gateway、
     daddr=backend、内层 TCP SYN 保留）—— 证明「解析→限速→连接跟踪→封装→转发」
     整条数据面在真实内核里跑通；
  4. 把 config 限速速率降为 0，注入新源 IP 的包，断言被 XDP_DROP 且 stats 计数
     ST_DROP_RATE 增长 —— 证明 DDoS 快速路径在真实内核里生效；
  5. ICMP ping 穿过钩子（PASS 路径）作为旁证。

设计说明：
  - 用 conntrack 预填命中（backend_idx=0）而非推算 maglev_lut 槽位——五元组固定，
    程序命中连接跟踪后跳过 Maglev，行为完全确定，且只需一条 map update。
  - veth 的 skb->xdp 转换会 skb_cow_head 补足 XDP_PACKET_HEADROOM，
    故 bpf_xdp_adjust_head 的 20B 头前推在 veth 上同样成立（真机网卡更无此问题）。
  - 全程只用系统自带工具：iproute2、bpftool、python3 标准库。

需要 root（CI 里 `sudo python3 ...`）。
"""

import os
import socket
import struct
import subprocess
import sys
import time

VETH0 = "xedge0"
VETH1 = "xedge1"
OBJ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xdp_edge.o")
GATEWAY_IP = "10.0.0.1"
BACKEND_IP = "10.0.0.100"

# 注入流：10.0.0.2:12345 -> 10.0.0.1:80  TCP SYN
SRC = bytes([10, 0, 0, 2])
DST = bytes([10, 0, 0, 1])
SPORT, DPORT = 12345, 80


def sh(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        print("FAIL:", cmd, "\n", r.stdout, r.stderr)
        sys.exit(1)
    return r


def log(msg):
    print(f"[datapath] {msg}", flush=True)


def mac_of(iface):
    r = sh(f"cat /sys/class/net/{iface}/address")
    return bytes.fromhex(r.stdout.strip().replace(":", ""))


def bpf_map_id(name):
    """从 bpftool map list 里按名字取 map id（输出形如 'xxx: name  id 123 ...'）。"""
    r = sh("bpftool map list -j")
    import json
    for m in json.loads(r.stdout):
        if m.get("name") == name:
            return m["id"]
    raise SystemExit(f"map {name} not found")


def map_update(mid, key, value):
    sh(f"bpftool map update id {mid} key {key.hex()} value {value.hex()}")


def csum16(data):
    """IPv4 header checksum（RFC 1071 单轮 + 进位折叠）。"""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_syn_pkt(src_mac, dst_mac, src_ip, dst_ip, sport, dport):
    """构造以太网 + IPv4 + TCP(SYN) 帧。src_ip 可变，供限速测试换源 IP。"""
    src_ip_b = socket.inet_aton(src_ip)
    dst_ip_b = socket.inet_aton(dst_ip)
    # TCP 头（无选项，20B），checksum 最后算
    tcp = struct.pack(
        "!HHIIHHHH", sport, dport, 0, 0, (5 << 12) | 0x02, 65535, 0, 0
    )  # data_offset=5, SYN
    # 伪头校验和
    pseudo = src_ip_b + dst_ip_b + b"\x00\x06" + struct.pack("!H", len(tcp))
    tcp_csum = csum16(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", tcp_csum) + tcp[18:]
    # IPv4 头（20B）
    ihl_ver = 0x45
    total = 20 + len(tcp)
    ident = 0
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s", ihl_ver, 0, total, ident, 0x4000, 64, 6, 0, src_ip_b, dst_ip_b
    )
    ip_csum = csum16(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", ip_csum) + ip_hdr[12:]
    eth = dst_mac + src_mac + b"\x08\x00"
    return eth + ip_hdr + tcp


def send_raw(iface, frame):
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) as s:
        s.bind((iface, 0))
        s.send(frame)


def sniff_ipip(iface, timeout_s, want_daddr):
    """在 iface 上收原始帧，找外层 IPIP（proto=4）且 daddr 匹配的，返回帧或 None。"""
    deadline = time.time() + timeout_s
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) as s:
        s.bind((iface, 0))
        s.settimeout(0.25)
        while time.time() < deadline:
            try:
                frame = s.recv(4096)
            except socket.timeout:
                continue
            if len(frame) < 14 + 20:
                continue
            eth_type = struct.unpack("!H", frame[12:14])[0]
            if eth_type != 0x0800:
                continue
            iph = frame[14:34]
            proto = iph[9]
            daddr = socket.inet_ntoa(iph[16:20])
            if proto == 4 and daddr == want_daddr:
                return frame
    return None


def setup():
    log("设置 veth 对")
    sh(f"ip link del {VETH0} 2>/dev/null || true")
    sh(f"ip link add {VETH0} type veth peer name {VETH1}")
    sh(f"ip link set {VETH0} up")
    sh(f"ip link set {VETH1} up")
    # 给 veth0 配 IP 供 ICMP PASS 旁证（PING 由主机栈应答）
    sh(f"ip addr add {GATEWAY_IP}/24 dev {VETH0}")
    sh(f"ip addr add 10.0.0.2/24 dev {VETH1}")


def attach():
    log("挂载 XDP 程序（验证器校验通过即加载成功）")
    sh(f"ip link set dev {VETH0} xdp obj {OBJ} sec xdp")


def fill_maps():
    log("预填 config / backends / conntrack")
    cfg = struct.pack(
        "<QQQII4s6s2s",
        65536,                     # rate_per_ns_fp: 1 token/ns（16.16 定点，远大于需要）
        1_000_000 * 65536,         # rate_burst: 100 万令牌
        1_000_000_000,             # syn_window_ns: 1s
        8,                         # syn_threshold: 窗口内需 ≥8 个 SYN 才算 flood
        2,                         # syn_ack_ratio
        socket.inet_aton(GATEWAY_IP),
        bytes.fromhex("112233445566"),
        b"\x00\x00",
    )
    # backend.ip = 10.0.0.100（u32 host 序，内核直接赋给外层头 __be32 daddr）
    be = struct.pack(
        "<I6sH", 0x0A000064, bytes.fromhex("aabbccddeeff"), 0,
    )
    ck = SRC + DST + struct.pack("!HH", SPORT, DPORT) + b"\x06" + b"\x00\x00\x00"
    cv = struct.pack("<IQ", 0, 0)  # backend_idx=0, last_seen=0

    map_update(bpf_map_id("config"), b"\x00\x00\x00\x00", cfg)
    map_update(bpf_map_id("backends"), b"\x00\x00\x00\x00", be)
    map_update(bpf_map_id("conntrack"), ck, cv)


def test_forward():
    log("测试①: 连接跟踪命中 → IPIP 封装 XDP_TX 转发")
    v0_mac, v1_mac = mac_of(VETH0), mac_of(VETH1)
    frame = build_syn_pkt(v1_mac, v0_mac, "10.0.0.2", "10.0.0.1", SPORT, DPORT)
    send_raw(VETH1, frame)
    out = sniff_ipip(VETH1, timeout_s=2.0, want_daddr=BACKEND_IP)
    if out is None:
        raise SystemExit("FAIL: 没有收到 IPIP 封装包（转发路径未生效）")
    outer = out[14:34]
    saddr = socket.inet_ntoa(outer[12:16])
    proto = outer[9]
    assert saddr == GATEWAY_IP and proto == 4, (saddr, proto)
    inner_ip = out[34:54]
    assert inner_ip[9] == 6, "内层应为 TCP"
    log(f"OK: 收到外层 IPIP saddr={saddr} daddr={BACKEND_IP} 内层 TCP ✓")


def test_rate_drop():
    log("测试②: 限速速率归零 → 新源 IP 被 XDP_DROP")
    cfg = struct.pack(
        "<QQQII4s6s2s",
        0,         # rate_per_ns_fp = 0 → 桶永远为空
        0,         # rate_burst = 0
        1_000_000_000, 8, 2, socket.inet_aton(GATEWAY_IP),
        bytes.fromhex("112233445566"), b"\x00\x00",
    )
    map_update(bpf_map_id("config"), b"\x00\x00\x00\x00", cfg)

    v0_mac, v1_mac = mac_of(VETH0), mac_of(VETH1)
    frame = build_syn_pkt(v1_mac, v0_mac, "10.0.0.9", "10.0.0.1", SPORT, DPORT)
    send_raw(VETH1, frame)
    out = sniff_ipip(VETH1, timeout_s=1.0, want_daddr=BACKEND_IP)
    if out is not None:
        raise SystemExit("FAIL: 限速归零后仍收到转发包")

    # 校验 ST_DROP_RATE（stats 下标 1）已增长。PERCPU_ARRAY 的 -j 输出形如
    # value: [ [per-cpu 0 的 8 个 u64], [per-cpu 1 ...], ... ]，逐 CPU 取下标 1 求和。
    r = sh("bpftool map dump id %d -j" % bpf_map_id("stats"))
    import json
    stats = json.loads(r.stdout)
    drop_rate = 0
    for entry in stats:
        val = entry["value"]
        if isinstance(val, list) and val and isinstance(val[0], list):
            for cpu in val:
                if len(cpu) > 1:
                    drop_rate += int(cpu[1])
        elif isinstance(val, list) and len(val) > 1:
            drop_rate += int(val[1])
    if drop_rate <= 0:
        raise SystemExit("FAIL: stats 未计 ST_DROP_RATE")
    log(f"OK: 包被丢弃，stats[ST_DROP_RATE]={drop_rate} ✓")


def test_pass():
    log("旁证: ICMP ping 走 PASS 路径")
    r = subprocess.run(
        f"ping -I {VETH1} -c 1 -W 1 {GATEWAY_IP}",
        shell=True, capture_output=True, text=True,
    )
    if r.returncode == 0:
        log("OK: ICMP PASS 路径工作 ✓")
    else:
        log("INFO: ping 未通（PASS 路径受主机栈配置影响，不阻塞）")


def main():
    setup()
    attach()
    fill_maps()
    test_forward()
    test_rate_drop()
    test_pass()
    log("ALL PASS: xdp-edge 内核数据面在 CI 实测通过")
    sh(f"ip link set dev {VETH0} xdp off", check=False)


if __name__ == "__main__":
    main()
