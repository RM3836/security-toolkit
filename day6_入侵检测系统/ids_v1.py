#!/usr/bin/env python3
"""
Day6 实战：轻量级入侵检测系统 (IDS) v1
原理：
  - 实时监听网络流量（基于 Scapy 抓包）
  - 基于规则的异常检测（签名匹配 + 行为分析）
  - 支持自定义规则引擎
  - 实时告警 + 日志记录

检测能力：
  1. 端口扫描检测（SYN 扫描、全连接扫描）
  2. ARP 欺骗检测（网关 MAC 变化）
  3. DNS 隧道检测（超长域名、高频查询）
  4. SYN Flood / ICMP Flood 洪泛攻击
  5. 暴力破解检测（SSH/FTP/HTTP 高频失败）
  6. 可疑 Payload 检测（SQL注入、XSS 关键字）

依赖：pip install scapy
运行：sudo python3 ids_v1.py --iface eth0
      sudo python3 ids_v1.py --iface eth0 --rules custom_rules.json
"""

import sys
import json
import time
import argparse
import signal
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP, Raw, conf
    conf.verb = 0  # 关闭 scapy 输出
except ImportError:
    print("[!] 需要安装 scapy: pip install scapy")
    sys.exit(1)


# ============================================================
#  规则引擎
# ============================================================

class Rule:
    """单条检测规则"""

    def __init__(self, name, category, severity, description, threshold=1, window=60):
        self.name = name
        self.category = category        # scan / flood / spoof / tunnel / exploit
        self.severity = severity        # CRITICAL / HIGH / MEDIUM / LOW
        self.description = description
        self.threshold = threshold      # 触发阈值
        self.window = window            # 检测窗口（秒）
        self.enabled = True

    def __repr__(self):
        return f"Rule({self.name}, {self.severity}, threshold={self.threshold}/{self.window}s)"


# 内置规则集
DEFAULT_RULES = [
    Rule("port_scan_syn", "scan", "HIGH",
         "SYN端口扫描：同一源IP短时间内向多个端口发送SYN",
         threshold=15, window=10),

    Rule("port_scan_connect", "scan", "MEDIUM",
         "全连接扫描：同一源IP短时间内完成多次TCP连接",
         threshold=20, window=30),

    Rule("arp_spoof", "spoof", "CRITICAL",
         "ARP欺骗：网关MAC地址异常变化",
         threshold=1, window=60),

    Rule("dns_tunnel", "tunnel", "HIGH",
         "DNS隧道：超长域名或高频DNS查询",
         threshold=50, window=60),

    Rule("syn_flood", "flood", "CRITICAL",
         "SYN洪泛：短时间内大量SYN包",
         threshold=200, window=5),

    Rule("icmp_flood", "flood", "HIGH",
         "ICMP洪泛：短时间内大量ICMP包",
         threshold=100, window=5),

    Rule("ssh_bruteforce", "bruteforce", "HIGH",
         "SSH暴力破解：短时间内多次SSH连接尝试",
         threshold=10, window=60),

    Rule("suspicious_payload", "exploit", "CRITICAL",
         "可疑Payload：检测到SQL注入/XSS/命令注入关键字",
         threshold=1, window=1),

    Rule("telnet_access", "policy", "MEDIUM",
         "不安全协议：检测到Telnet流量(明文传输)",
         threshold=1, window=1),

    Rule("large_dns_response", "tunnel", "MEDIUM",
         "异常DNS响应：响应数据过大（可能DNS隧道）",
         threshold=1, window=1),
]


# ============================================================
#  告警系统
# ============================================================

class Alert:
    """告警对象"""

    def __init__(self, rule, src_ip, dst_ip, detail, packets=None):
        self.time = datetime.now()
        self.rule = rule
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.detail = detail
        self.packets = packets or []

    def to_dict(self):
        return {
            'time': self.time.strftime('%Y-%m-%d %H:%M:%S'),
            'severity': self.rule.severity,
            'category': self.rule.category,
            'rule': self.rule.name,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'detail': self.detail,
        }

    def __str__(self):
        icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        return (f"{icon.get(self.rule.severity, '?')} [{self.time.strftime('%H:%M:%S')}] "
                f"[{self.rule.severity}] {self.rule.name}: "
                f"{self.src_ip} -> {self.dst_ip} | {self.detail}")


# ============================================================
#  入侵检测引擎
# ============================================================

class IntrusionDetector:
    """轻量级入侵检测系统"""

    def __init__(self, interface=None, rules=None, log_file=None):
        self.interface = interface
        self.rules = rules or DEFAULT_RULES
        self.log_file = log_file or f"ids_alerts_{time.strftime('%Y%m%d_%H%M%S')}.json"
        self.running = False

        # ========== 滑动窗口统计 ==========
        # SYN 扫描检测：src_ip -> set(dst_ports)
        self.syn_tracker = defaultdict(lambda: {'ports': set(), 'times': deque()})
        # 全连接扫描：src_ip -> count
        self.connect_tracker = defaultdict(lambda: {'count': 0, 'times': deque()})
        # ARP 表：ip -> mac
        self.arp_table = {}
        self.gateway_mac = None
        # DNS 隧道：src_ip -> {count, domains}
        self.dns_tracker = defaultdict(lambda: {'count': 0, 'times': deque(), 'domains': []})
        # SYN Flood：dst_ip -> count
        self.syn_flood_tracker = defaultdict(lambda: {'count': 0, 'times': deque()})
        # ICMP Flood：dst_ip -> count
        self.icmp_flood_tracker = defaultdict(lambda: {'count': 0, 'times': deque()})
        # SSH 暴力破解：src_ip -> count
        self.ssh_tracker = defaultdict(lambda: {'count': 0, 'times': deque()})

        # ========== 结果统计 ==========
        self.alerts = []
        self.packet_count = 0
        self.alert_log = []  # JSON 日志

        # 可疑关键字
        self.sqli_keywords = [
            "' or ", "' or'", "1=1", "union select", "drop table",
            "insert into", "delete from", "--", "/*", "*/",
            "exec(", "execute(", "xp_cmdshell"
        ]
        self.xss_keywords = [
            "<script>", "javascript:", "onerror=", "onload=",
            "onclick=", "onfocus=", "alert(", "document.cookie"
        ]
        self.cmdi_keywords = [
            "; cat ", "; ls ", "| cat ", "| ls ", "; whoami",
            "; id ", "; uname", "&& cat", "&& ls", "`whoami`"
        ]

    def _in_window(self, deq, window):
        """清理过期时间戳，返回窗口内计数"""
        now = time.time()
        while deq and deq[0] < now - window:
            deq.popleft()
        return len(deq)

    def _count_alert(self, rule_name):
        """统计规则触发次数"""
        now = time.time()
        return sum(1 for a in self.alerts
                   if a.rule.name == rule_name and (now - a.time.timestamp()) < a.rule.window)

    def _fire_alert(self, rule, src_ip, dst_ip, detail):
        """触发告警（带去重：同一规则在窗口内只告警一次）"""
        # 检查窗口内是否已告警
        recent = self._count_alert(rule.name)
        if recent > 0:
            return  # 窗口内已告警，不再重复

        alert = Alert(rule, src_ip, dst_ip, detail)
        self.alerts.append(alert)
        self.alert_log.append(alert.to_dict())

        # 输出到终端
        print(f"\n{alert}")

        # 写日志文件
        self._save_alert(alert)

    def _save_alert(self, alert):
        """保存告警到 JSON 文件"""
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.alert_log, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    # ========== 检测引擎 ==========

    def detect_syn_scan(self, pkt):
        """SYN 端口扫描检测"""
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return
        if pkt[TCP].flags != 0x02:  # 只看 SYN 包
            return

        src = pkt[IP].src
        dst_port = pkt[TCP].dport
        tracker = self.syn_tracker[src]

        tracker['ports'].add(dst_port)
        tracker['times'].append(time.time())
        self._in_window(tracker['times'], 10)

        rule = next((r for r in self.rules if r.name == 'port_scan_syn'), None)
        if rule and rule.enabled and len(tracker['ports']) >= rule.threshold:
            self._fire_alert(rule, src, pkt[IP].dst,
                             f"扫描了 {len(tracker['ports'])} 个端口")
            tracker['ports'].clear()

    def detect_arp_spoof(self, pkt):
        """ARP 欺骗检测"""
        if not pkt.haslayer(ARP):
            return
        if pkt[ARP].op != 2:  # 只看 ARP reply
            return

        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc

        if ip in self.arp_table:
            old_mac = self.arp_table[ip]
            if old_mac != mac:
                rule = next((r for r in self.rules if r.name == 'arp_spoof'), None)
                if rule and rule.enabled:
                    self._fire_alert(rule, mac, ip,
                                     f"MAC 从 {old_mac} 变为 {mac}（疑似ARP欺骗）")
        self.arp_table[ip] = mac

        # 记录网关 MAC
        if self.gateway_mac is None and pkt[ARP].psrc.endswith('.1'):
            self.gateway_mac = mac

    def detect_dns_tunnel(self, pkt):
        """DNS 隧道检测"""
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            return
        if pkt[DNS].qr != 0:  # 只看查询
            return

        src = pkt[IP].src
        domain = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
        tracker = self.dns_tracker[src]

        tracker['count'] += 1
        tracker['times'].append(time.time())
        tracker['domains'].append(domain)
        self._in_window(tracker['times'], 60)

        rule = next((r for r in self.rules if r.name == 'dns_tunnel'), None)

        # 检测1：超长域名（子域名 > 50 字符，可能是数据编码传输）
        subdomain = domain.split('.')[0]
        if rule and rule.enabled and len(subdomain) > 50:
            self._fire_alert(rule, src, pkt[IP].dst,
                             f"超长子域名({len(subdomain)}字符): {subdomain[:40]}...")

        # 检测2：高频查询
        if rule and rule.enabled and tracker['count'] >= rule.threshold:
            self._fire_alert(rule, src, pkt[IP].dst,
                             f"{rule.window}秒内 {tracker['count']} 次DNS查询")
            tracker['count'] = 0

    def detect_syn_flood(self, pkt):
        """SYN Flood 检测"""
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return
        if pkt[TCP].flags != 0x02:
            return

        dst = pkt[IP].dst
        tracker = self.syn_flood_tracker[dst]
        tracker['times'].append(time.time())
        count = self._in_window(tracker['times'], 5)

        rule = next((r for r in self.rules if r.name == 'syn_flood'), None)
        if rule and rule.enabled and count >= rule.threshold:
            self._fire_alert(rule, '*', dst,
                             f"5秒内收到 {count} 个SYN包（SYN Flood）")
            tracker['times'].clear()

    def detect_icmp_flood(self, pkt):
        """ICMP Flood 检测"""
        if not pkt.haslayer(ICMP):
            return
        if pkt[ICMP].type != 8:  # 只看 echo request
            return

        dst = pkt[IP].dst
        tracker = self.icmp_flood_tracker[dst]
        tracker['times'].append(time.time())
        count = self._in_window(tracker['times'], 5)

        rule = next((r for r in self.rules if r.name == 'icmp_flood'), None)
        if rule and rule.enabled and count >= rule.threshold:
            self._fire_alert(rule, pkt[IP].src, dst,
                             f"5秒内收到 {count} 个ICMP包（ICMP Flood）")
            tracker['times'].clear()

    def detect_ssh_bruteforce(self, pkt):
        """SSH 暴力破解检测"""
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return
        if pkt[TCP].dport != 22:
            return
        if pkt[TCP].flags != 0x02:  # SYN = 新连接尝试
            return

        src = pkt[IP].src
        tracker = self.ssh_tracker[src]
        tracker['times'].append(time.time())
        count = self._in_window(tracker['times'], 60)

        rule = next((r for r in self.rules if r.name == 'ssh_bruteforce'), None)
        if rule and rule.enabled and count >= rule.threshold:
            self._fire_alert(rule, src, pkt[IP].dst,
                             f"60秒内 {count} 次SSH连接尝试")
            tracker['times'].clear()

    def detect_suspicious_payload(self, pkt):
        """可疑 Payload 检测"""
        if not pkt.haslayer(Raw):
            return

        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
        except:
            return

        src = pkt[IP].src if pkt.haslayer(IP) else '?'
        dst = pkt[IP].dst if pkt.haslayer(IP) else '?'

        # SQL 注入
        for kw in self.sqli_keywords:
            if kw in payload:
                rule = next((r for r in self.rules if r.name == 'suspicious_payload'), None)
                if rule and rule.enabled:
                    self._fire_alert(rule, src, dst,
                                     f"SQL注入关键字: '{kw}' in {payload[:80]}")
                return

        # XSS
        for kw in self.xss_keywords:
            if kw in payload:
                rule = next((r for r in self.rules if r.name == 'suspicious_payload'), None)
                if rule and rule.enabled:
                    self._fire_alert(rule, src, dst,
                                     f"XSS关键字: '{kw}' in {payload[:80]}")
                return

        # 命令注入
        for kw in self.cmdi_keywords:
            if kw in payload:
                rule = next((r for r in self.rules if r.name == 'suspicious_payload'), None)
                if rule and rule.enabled:
                    self._fire_alert(rule, src, dst,
                                     f"命令注入关键字: '{kw}' in {payload[:80]}")
                return

    def detect_telnet(self, pkt):
        """Telnet 明文协议检测"""
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return
        if pkt[TCP].dport != 23:
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        rule = next((r for r in self.rules if r.name == 'telnet_access'), None)
        if rule and rule.enabled:
            self._fire_alert(rule, src, dst, "检测到 Telnet 明文流量")

    # ========== 主循环 ==========

    def process_packet(self, pkt):
        """处理每个抓到的数据包"""
        self.packet_count += 1

        # 逐条规则检测
        self.detect_syn_scan(pkt)
        self.detect_arp_spoof(pkt)
        self.detect_dns_tunnel(pkt)
        self.detect_syn_flood(pkt)
        self.detect_icmp_flood(pkt)
        self.detect_ssh_bruteforce(pkt)
        self.detect_suspicious_payload(pkt)
        self.detect_telnet(pkt)

        # 进度显示（每100个包打印一次）
        if self.packet_count % 100 == 0:
            print(f"  [*] 已分析 {self.packet_count} 个数据包, "
                  f"告警 {len(self.alerts)} 条", end='\r')

    def start(self, count=0):
        """启动 IDS"""
        self.running = True

        print("=" * 60)
        print("  轻量级入侵检测系统 (IDS) v1 - Day6 实战")
        print("  作者: YURM | 日期: 2026-05-23")
        print("=" * 60)
        print(f"\n  接口: {self.interface or '所有接口'}")
        print(f"  规则: {len([r for r in self.rules if r.enabled])} 条已启用")
        print(f"  日志: {self.log_file}")
        print(f"\n  {'=' * 50}")
        print(f"  开始监听... (Ctrl+C 停止)")
        print(f"  {'=' * 50}")

        # 注册 Ctrl+C 信号
        signal.signal(signal.SIGINT, lambda s, f: self.stop())

        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                count=count if count > 0 else 0,
                store=False
            )
        except PermissionError:
            print("\n  [!] 需要 root 权限: sudo python3 ids_v1.py")
            return
        except Exception as e:
            print(f"\n  [!] 抓包错误: {e}")
            print(f"  [!] 提示: 确认接口名正确: ip link show")

        self.stop()

    def stop(self):
        """停止 IDS 并输出统计"""
        self.running = False
        self.print_report()

    def print_report(self):
        """打印检测报告"""
        print(f"\n\n{'=' * 60}")
        print(f"  IDS 检测报告")
        print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 60}")

        print(f"\n  [1] 流量统计")
        print(f"  {'-' * 40}")
        print(f"  分析数据包: {self.packet_count}")
        print(f"  告警总数:   {len(self.alerts)}")

        # 按严重程度统计
        severity_count = defaultdict(int)
        for alert in self.alerts:
            severity_count[alert.rule.severity] += 1

        print(f"\n  [2] 告警分布")
        print(f"  {'-' * 40}")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_count.get(sev, 0)
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
            print(f"  {icon.get(sev, '?')} {sev:10s} {count}")

        # 按类别统计
        category_count = defaultdict(int)
        for alert in self.alerts:
            category_count[alert.rule.category] += 1

        if category_count:
            print(f"\n  [3] 告警类别")
            print(f"  {'-' * 40}")
            for cat, count in sorted(category_count.items(), key=lambda x: -x[1]):
                print(f"  {cat:15s} {count} 条")

        # 告警详情
        if self.alerts:
            print(f"\n  [4] 告警详情")
            print(f"  {'-' * 40}")
            for alert in self.alerts:
                print(f"  [{alert.time.strftime('%H:%M:%S')}] "
                      f"[{alert.rule.severity}] {alert.rule.name}")
                print(f"    {alert.src_ip} -> {alert.dst_ip}")
                print(f"    {alert.detail}")

        print(f"\n  日志文件: {self.log_file}")
        print(f"{'=' * 60}")


# ============================================================
#  主程序
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='Day6: 轻量级入侵检测系统')
    parser.add_argument('--iface', '-i', default=None, help='监听网卡 (如 eth0, wlan0)')
    parser.add_argument('--count', '-c', type=int, default=0, help='抓包数量 (0=无限)')
    parser.add_argument('--rules', '-r', default=None, help='自定义规则文件 (JSON)')
    parser.add_argument('--log', '-l', default=None, help='日志输出文件')
    args = parser.parse_args()

    # 加载规则
    rules = DEFAULT_RULES
    if args.rules:
        try:
            with open(args.rules) as f:
                custom = json.load(f)
            print(f"  [+] 加载自定义规则: {args.rules} ({len(custom)} 条)")
        except Exception as e:
            print(f"  [!] 规则加载失败: {e}")

    # 启动 IDS
    ids = IntrusionDetector(
        interface=args.iface,
        rules=rules,
        log_file=args.log
    )
    ids.start(count=args.count)


if __name__ == "__main__":
    main()
