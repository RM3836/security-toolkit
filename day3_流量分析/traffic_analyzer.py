#!/usr/bin/env python3
"""
Day3 实战：网络流量分析器
功能：
  1. 实时抓包分析（TCP/UDP/ICMP/DNS/HTTP）
  2. 流量统计（协议分布、TOP IP、TOP 端口）
  3. 异常检测（端口扫描、DNS 隧道、大量连接）
  4. 保存抓包结果（PCAP + JSON 报告）

依赖：pip install scapy
用法：
  python3 traffic_analyzer.py capture -i eth0 -c 100      # 抓100个包
  python3 traffic_analyzer.py capture -i eth0 -t 30       # 抓30秒
  python3 traffic_analyzer.py analyze capture.pcap        # 分析PCAP文件
  python3 traffic_analyzer.py detect -i eth0 -t 60        # 抓60秒做异常检测
"""

import sys
import time
import json
import os
from collections import Counter, defaultdict
from datetime import datetime

try:
    from scapy.all import (
        sniff, wrpcap, rdpcap, IP, TCP, UDP, ICMP, DNS,
        DNSQR, Raw, conf
    )
    conf.verb = 0  # 关闭 scapy 冗余输出
except ImportError:
    print("  [!] 需要安装 scapy: pip install scapy")
    sys.exit(1)


# ========== 协议识别 ==========
PROTOCOL_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-S", 68: "DHCP-C",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def identify_service(port):
    """端口号 -> 服务名"""
    return PROTOCOL_MAP.get(port, "unknown")


def analyze_packet(pkt):
    """分析单个数据包，返回结构化信息"""
    info = {
        'time': time.time(),
        'len': len(pkt),
        'proto': 'OTHER',
        'src': '',
        'dst': '',
        'sport': 0,
        'dport': 0,
        'info': ''
    }

    if IP in pkt:
        info['src'] = pkt[IP].src
        info['dst'] = pkt[IP].dst

    if TCP in pkt:
        info['proto'] = 'TCP'
        info['sport'] = pkt[TCP].sport
        info['dport'] = pkt[TCP].dport
        flags = pkt[TCP].flags
        flag_str = str(flags)
        info['info'] = 'Flags: %s' % flag_str

        # HTTP 检测
        if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
            if Raw in pkt:
                payload = pkt[Raw].load[:200].decode('utf-8', errors='ignore')
                if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                    info['proto'] = 'HTTP'
                    info['info'] = payload.split('\r\n')[0][:80]
                elif payload.startswith('HTTP/'):
                    info['proto'] = 'HTTP'
                    info['info'] = payload.split('\r\n')[0][:80]

    elif UDP in pkt:
        info['proto'] = 'UDP'
        info['sport'] = pkt[UDP].sport
        info['dport'] = pkt[UDP].dport

        # DNS 检测
        if DNS in pkt:
            info['proto'] = 'DNS'
            if pkt[DNS].qr == 0:  # 查询
                if pkt[DNS].qd:
                    info['info'] = 'Query: %s' % pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
            else:  # 响应
                info['info'] = 'Response: %d answers' % pkt[DNS].ancount

    elif ICMP in pkt:
        info['proto'] = 'ICMP'
        icmp_type = pkt[ICMP].type
        type_map = {0: 'Echo Reply', 8: 'Echo Request', 3: 'Dest Unreachable', 11: 'Time Exceeded'}
        info['info'] = type_map.get(icmp_type, 'Type %d' % icmp_type)

    return info


class TrafficStats:
    """流量统计器"""

    def __init__(self):
        self.packets = []
        self.protocols = Counter()
        self.src_ips = Counter()
        self.dst_ips = Counter()
        self.dst_ports = Counter()
        self.src_ports = Counter()
        self.bytes_total = 0
        self.start_time = None
        self.end_time = None
        self.connections = defaultdict(set)  # src_ip -> set of dst_ports
        self.dns_queries = []

    def add(self, pkt_info):
        """添加一个数据包的分析结果"""
        self.packets.append(pkt_info)
        self.protocols[pkt_info['proto']] += 1
        self.bytes_total += pkt_info['len']

        if pkt_info['src']:
            self.src_ips[pkt_info['src']] += 1
        if pkt_info['dst']:
            self.dst_ips[pkt_info['dst']] += 1
        if pkt_info['dport']:
            self.dst_ports[pkt_info['dport']] += 1
        if pkt_info['sport']:
            self.src_ports[pkt_info['sport']] += 1

        if not self.start_time:
            self.start_time = pkt_info['time']
        self.end_time = pkt_info['time']

        # 记录连接关系（用于端口扫描检测）
        if pkt_info['proto'] == 'TCP' and pkt_info['src'] and pkt_info['dport']:
            self.connections[pkt_info['src']].add(pkt_info['dport'])

        # 记录 DNS 查询
        if pkt_info['proto'] == 'DNS' and 'Query:' in pkt_info.get('info', ''):
            self.dns_queries.append(pkt_info['info'].replace('Query: ', ''))

    def report(self):
        """生成统计报告"""
        duration = self.end_time - self.start_time if self.start_time and self.end_time else 0

        report = []
        report.append("=" * 55)
        report.append("  流量分析报告")
        report.append("  时间: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        report.append("=" * 55)
        report.append("")
        report.append("  --- 总体统计 ---")
        report.append("  数据包总数: %d" % len(self.packets))
        report.append("  总字节数:   %s" % format_bytes(self.bytes_total))
        report.append("  持续时间:   %.1f 秒" % duration)
        if duration > 0:
            pps = len(self.packets) / duration
            bps = self.bytes_total / duration
            report.append("  包速率:     %.1f pps" % pps)
            report.append("  带宽:       %s" % format_bytes(bps) + "/s")
        report.append("")

        report.append("  --- 协议分布 ---")
        for proto, count in self.protocols.most_common():
            pct = count / len(self.packets) * 100 if self.packets else 0
            bar = "█" * int(pct / 3)
            report.append("  %-10s %5d (%5.1f%%) %s" % (proto, count, pct, bar))
        report.append("")

        report.append("  --- TOP 10 源 IP ---")
        for ip, count in self.src_ips.most_common(10):
            report.append("  %-18s %5d 包" % (ip, count))
        report.append("")

        report.append("  --- TOP 10 目标 IP ---")
        for ip, count in self.dst_ips.most_common(10):
            report.append("  %-18s %5d 包" % (ip, count))
        report.append("")

        report.append("  --- TOP 10 目标端口 ---")
        for port, count in self.dst_ports.most_common(10):
            service = identify_service(port)
            report.append("  %-6d %-15s %5d 包" % (port, service, count))
        report.append("")

        if self.dns_queries:
            report.append("  --- DNS 查询记录 (前20) ---")
            seen = set()
            for q in self.dns_queries[:50]:
                if q not in seen:
                    seen.add(q)
                    report.append("  %s" % q)
                if len(seen) >= 20:
                    break
            report.append("")

        return "\n".join(report)

    def detect_anomalies(self):
        """异常检测"""
        alerts = []
        duration = self.end_time - self.start_time if self.start_time and self.end_time else 0

        # 1. 端口扫描检测：一个 IP 在短时间内访问了大量不同端口
        for ip, ports in self.connections.items():
            if len(ports) > 15:
                alerts.append({
                    'level': 'HIGH',
                    'type': '端口扫描',
                    'detail': '%s 访问了 %d 个不同端口: %s' % (
                        ip, len(ports),
                        ', '.join(str(p) for p in sorted(ports)[:20]) + '...'
                    ),
                    'recommend': '检查该主机是否在进行端口扫描，考虑封禁 IP'
                })

        # 2. DNS 隧道检测：单个域名的子域名过长或过多
        domain_counter = Counter()
        for q in self.dns_queries:
            parts = q.rstrip('.').split('.')
            if len(parts) >= 3:
                # 取最后两级作为主域名
                domain = '.'.join(parts[-2:])
                domain_counter[domain] += 1
                # 子域名过长可能是 DNS 隧道
                if len(parts[0]) > 30:
                    alerts.append({
                        'level': 'MEDIUM',
                        'type': '疑似DNS隧道',
                        'detail': '超长子域名: %s' % q[:80],
                        'recommend': '检查是否为 DNS 隧道数据外泄'
                    })

        for domain, count in domain_counter.most_common(5):
            if count > 50:
                alerts.append({
                    'level': 'LOW',
                    'type': 'DNS 查询异常',
                    'detail': '域名 %s 被查询 %d 次' % (domain, count),
                    'recommend': '检查是否为 DGA 域名或大量 DNS 请求'
                })

        # 3. SYN Flood 检测
        syn_count = Counter()
        for pkt in self.packets:
            if pkt['proto'] == 'TCP' and 'Flags: S' in pkt.get('info', '') and 'Flags: SA' not in pkt.get('info', ''):
                syn_count[pkt['dst']] += 1

        for ip, count in syn_count.most_common(5):
            if count > 50:
                alerts.append({
                    'level': 'HIGH',
                    'type': 'SYN Flood',
                    'detail': '向 %s 发送了 %d 个 SYN 包' % (ip, count),
                    'recommend': '可能是 SYN Flood 攻击，检查防火墙规则'
                })

        # 4. 大量 ICMP（可能是 ping flood）
        icmp_count = self.protocols.get('ICMP', 0)
        if icmp_count > 100 and duration > 0:
            rate = icmp_count / duration
            if rate > 10:
                alerts.append({
                    'level': 'MEDIUM',
                    'type': 'ICMP Flood',
                    'detail': '%d 个 ICMP 包，速率 %.1f/s' % (icmp_count, rate),
                    'recommend': '可能是 Ping Flood，考虑限制 ICMP 速率'
                })

        # 5. Telnet 明文传输
        telnet_count = self.dst_ports.get(23, 0) + self.src_ports.get(23, 0)
        if telnet_count > 0:
            alerts.append({
                'level': 'LOW',
                'type': '不安全协议',
                'detail': '检测到 %d 个 Telnet 包（明文传输）' % telnet_count,
                'recommend': '建议使用 SSH 替代 Telnet'
            })

        return alerts


def format_bytes(n):
    """格式化字节数"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if n < 1024:
            return "%.1f %s" % (n, unit)
        n /= 1024
    return "%.1f TB" % n


def cmd_capture(args):
    """实时抓包"""
    iface = None
    count = 0
    timeout = 0
    save_pcap = None

    # 解析参数
    i = 0
    while i < len(args):
        if args[i] == '-i' and i + 1 < len(args):
            iface = args[i + 1]
            i += 2
        elif args[i] == '-c' and i + 1 < len(args):
            count = int(args[i + 1])
            i += 2
        elif args[i] == '-t' and i + 1 < len(args):
            timeout = int(args[i + 1])
            i += 2
        elif args[i] == '-o' and i + 1 < len(args):
            save_pcap = args[i + 1]
            i += 2
        else:
            i += 1

    if not count and not timeout:
        count = 50  # 默认抓50个包

    print("\n  [*] 开始抓包...")
    if iface:
        print("  [*] 接口: %s" % iface)
    if count:
        print("  [*] 包数量: %d" % count)
    if timeout:
        print("  [*] 超时: %d 秒" % timeout)
    print()

    stats = TrafficStats()
    raw_packets = []

    def process_packet(pkt):
        raw_packets.append(pkt)
        info = analyze_packet(pkt)
        stats.add(info)

        # 实时打印
        proto = info['proto']
        src = "%s:%s" % (info['src'], info['sport']) if info['sport'] else info['src']
        dst = "%s:%s" % (info['dst'], info['dport']) if info['dport'] else info['dst']
        extra = info['info'][:50] if info['info'] else ''

        color = {
            'TCP': '', 'UDP': '', 'ICMP': '',
            'DNS': '', 'HTTP': '', 'OTHER': ''
        }.get(proto, '')

        print("  %-6s %-25s -> %-25s %s %s" % (
            proto, src[:25], dst[:25], 
            "[%s]" % extra if extra else '', color))

    try:
        sniff(
            iface=iface,
            count=count,
            timeout=timeout,
            prn=process_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\n  [!] 用户中断")

    # 保存 PCAP
    if save_pcap and raw_packets:
        wrpcap(save_pcap, raw_packets)
        print("\n  [*] PCAP 已保存: %s" % save_pcap)
    elif raw_packets:
        pcap_file = "capture_%s.pcap" % time.strftime("%Y%m%d_%H%M%S")
        wrpcap(pcap_file, raw_packets)
        print("\n  [*] PCAP 已保存: %s" % pcap_file)

    # 输出报告
    print("\n" + stats.report())

    # 保存 JSON
    json_file = "traffic_%s.json" % time.strftime("%Y%m%d_%H%M%S")
    report_data = {
        'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'packets': len(stats.packets),
        'bytes': stats.bytes_total,
        'protocols': dict(stats.protocols),
        'top_src_ips': dict(stats.src_ips.most_common(10)),
        'top_dst_ips': dict(stats.dst_ips.most_common(10)),
        'top_dst_ports': {str(k): v for k, v in stats.dst_ports.most_common(10)},
    }
    with open(json_file, 'w') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    print("  JSON 报告: %s" % json_file)


def cmd_analyze(args):
    """分析 PCAP 文件"""
    if not args:
        print("  [!] 用法: analyze <pcap文件>")
        return

    pcap_file = args[0]
    if not os.path.exists(pcap_file):
        print("  [!] 文件不存在: %s" % pcap_file)
        return

    print("\n  [*] 读取 PCAP: %s" % pcap_file)
    packets = rdpcap(pcap_file)
    print("  [*] 共 %d 个数据包\n" % len(packets))

    stats = TrafficStats()
    for pkt in packets:
        info = analyze_packet(pkt)
        stats.add(info)

    print(stats.report())

    # 异常检测
    alerts = stats.detect_anomalies()
    if alerts:
        print("\n  --- 安全告警 ---")
        for a in alerts:
            icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(a['level'], '⚪')
            print("  %s [%s] %s" % (icon, a['level'], a['type']))
            print("     %s" % a['detail'])
            print("     建议: %s" % a['recommend'])
            print()


def cmd_detect(args):
    """实时异常检测"""
    iface = None
    timeout = 60

    i = 0
    while i < len(args):
        if args[i] == '-i' and i + 1 < len(args):
            iface = args[i + 1]
            i += 2
        elif args[i] == '-t' and i + 1 < len(args):
            timeout = int(args[i + 1])
            i += 2
        else:
            i += 1

    print("\n  [*] 异常检测模式 - 抓包 %d 秒" % timeout)
    print("  [*] 检测项目: 端口扫描 / SYN Flood / DNS隧道 / ICMP Flood\n")

    stats = TrafficStats()
    raw_packets = []
    count = [0]

    def process_packet(pkt):
        raw_packets.append(pkt)
        info = analyze_packet(pkt)
        stats.add(info)
        count[0] += 1
        if count[0] % 50 == 0:
            print("  ... 已捕获 %d 包" % count[0])

    try:
        sniff(
            iface=iface,
            timeout=timeout,
            prn=process_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\n  [!] 用户中断")

    # 保存 PCAP
    pcap_file = "detect_%s.pcap" % time.strftime("%Y%m%d_%H%M%S")
    if raw_packets:
        wrpcap(pcap_file, raw_packets)

    # 统计报告
    print("\n" + stats.report())

    # 异常检测
    alerts = stats.detect_anomalies()
    if alerts:
        print("\n  " + "=" * 55)
        print("  安全告警 (共 %d 条)" % len(alerts))
        print("  " + "=" * 55)
        for a in alerts:
            icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(a['level'], '⚪')
            print("\n  %s [%s] %s" % (icon, a['level'], a['type']))
            print("     详情: %s" % a['detail'])
            print("     建议: %s" % a['recommend'])
    else:
        print("\n  ✅ 未检测到异常流量")

    print("\n  PCAP 已保存: %s" % pcap_file)


def cmd_list_ifaces(args):
    """列出网络接口"""
    print("\n  可用网络接口:")
    from scapy.arch import get_if_list
    for iface in get_if_list():
        print("    - %s" % iface)


def main():
    print("=" * 55)
    print("  网络流量分析器 - Day3 实战")
    print("  作者: YURM | 日期: 2026-05-20")
    print("=" * 55)

    if len(sys.argv) < 2:
        print("""
用法:
  实时抓包:    python3 traffic_analyzer.py capture -i eth0 -c 100
  按时间抓包:  python3 traffic_analyzer.py capture -i eth0 -t 30
  分析PCAP:    python3 traffic_analyzer.py analyze capture.pcap
  异常检测:    python3 traffic_analyzer.py detect -i eth0 -t 60
  列出接口:    python3 traffic_analyzer.py ifaces

参数:
  -i <接口>     网络接口名
  -c <数量>     抓包数量
  -t <秒数>     抓包时长
  -o <文件>     保存PCAP路径
""")
        return

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == 'capture':
        cmd_capture(args)
    elif cmd == 'analyze':
        cmd_analyze(args)
    elif cmd == 'detect':
        cmd_detect(args)
    elif cmd == 'ifaces':
        cmd_list_ifaces(args)
    else:
        print("  [!] 未知命令: %s" % cmd)


if __name__ == "__main__":
    main()
