#!/usr/bin/env python3
"""
Day7 实战：安全工具集成平台 v1（终极大集成）
原理：
  - 将 Day1~Day6 所有工具集成到一个统一平台
  - 交互式菜单 + 一键自动化扫描
  - 统一报告输出

集成模块：
  1. Day1 - 端口扫描器 (port_scanner)
  2. Day2 - SSH 批量管理 (ssh_manager)
  3. Day3 - 流量分析器 (traffic_analyzer)
  4. Day4 - Web 漏洞扫描器 (web_scanner)
  5. Day5 - 日志分析系统 (log_analyzer)
  6. Day6 - 入侵检测系统 (ids)
  7. 一键综合安全评估 (all-in-one)

依赖：pip install requests scapy paramiko
运行：python3 security_platform_v1.py
"""

import os
import sys
import json
import time
import socket
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========== 可选依赖 ==========
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, sr1, RandShort, conf
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


# ============================================================
#  模块 1：端口扫描器
# ============================================================

class PortScanner:
    """TCP 端口扫描器（精简版）"""

    COMMON_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
        443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
        6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
        27017: 'MongoDB', 9200: 'Elasticsearch',
    }

    def __init__(self, target, ports=None, timeout=1, threads=100):
        self.target = target
        self.ports = ports or list(self.COMMON_PORTS.keys())
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.services = {}

    def scan_port(self, port):
        """扫描单个端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return port, result == 0
        except:
            return port, False

    def get_service(self, port):
        """获取服务名"""
        try:
            return socket.getservbyport(port, 'tcp')
        except:
            return self.COMMON_PORTS.get(port, 'unknown')

    def run(self):
        """执行扫描"""
        print(f"\n  [模块1] 端口扫描")
        print(f"  {'-' * 40}")
        print(f"  目标: {self.target}")
        print(f"  端口范围: {len(self.ports)} 个常用端口")
        print(f"  线程数: {self.threads}")

        start = time.time()
        self.open_ports = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in self.ports}
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    service = self.get_service(port)
                    self.open_ports.append(port)
                    self.services[port] = service
                    print(f"  ✅ {port:5d}/tcp  OPEN  ({service})")

        elapsed = time.time() - start
        print(f"\n  扫描完成: {len(self.open_ports)} 个开放端口, 耗时 {elapsed:.1f}s")

        return {
            'target': self.target,
            'open_ports': self.open_ports,
            'services': self.services,
            'scan_time': elapsed
        }


# ============================================================
#  模块 2：SSH 批量管理
# ============================================================

class SSHManager:
    """SSH 批量连接管理器（精简版）"""

    def __init__(self, hosts, username='root', password=None, key_file=None, timeout=5):
        self.hosts = hosts  # [(ip, port), ...]
        self.username = username
        self.password = password
        self.key_file = key_file
        self.timeout = timeout
        self.results = {}

    def exec_command(self, host, port, command):
        """在单台主机上执行命令"""
        if not HAS_PARAMIKO:
            return {'host': host, 'error': 'paramiko not installed'}

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            kwargs = {'hostname': host, 'port': port,
                      'username': self.username, 'timeout': self.timeout}
            if self.key_file:
                kwargs['key_filename'] = self.key_file
            else:
                kwargs['password'] = self.password
            client.connect(**kwargs)

            stdin, stdout, stderr = client.exec_command(command, timeout=10)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            return {'host': host, 'port': port, 'output': output, 'error': error}
        except Exception as e:
            return {'host': host, 'port': port, 'error': str(e)}
        finally:
            client.close()

    def run_command(self, command):
        """批量执行命令"""
        print(f"\n  [模块2] SSH 批量管理")
        print(f"  {'-' * 40}")
        print(f"  主机数: {len(self.hosts)}")
        print(f"  用户: {self.username}")
        print(f"  命令: {command}")

        if not HAS_PARAMIKO:
            print("  [!] 需要安装 paramiko: pip install paramiko")
            return {}

        self.results = {}
        for host, port in self.hosts:
            print(f"  → {host}:{port} ...", end=' ')
            result = self.exec_command(host, port, command)
            if result.get('error'):
                print(f"❌ {result['error'][:40]}")
            else:
                print(f"✅")
                if result.get('output'):
                    for line in result['output'].strip().split('\n')[:5]:
                        print(f"    {line}")
            self.results[host] = result

        return self.results


# ============================================================
#  模块 3：Web 漏洞扫描器
# ============================================================

class WebScanner:
    """Web 漏洞扫描器（精简版）"""

    def __init__(self, target, timeout=10):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.findings = []

    def check_headers(self):
        """检查安全头"""
        try:
            resp = requests.get(self.target, timeout=self.timeout, verify=False,
                                headers={'User-Agent': 'SecurityScanner/1.0'})
            headers = resp.headers

            # 安全头检测
            for header in ['X-Frame-Options', 'X-Content-Type-Options',
                           'Content-Security-Policy', 'Strict-Transport-Security']:
                if header not in headers:
                    self.findings.append({
                        'severity': 'LOW', 'type': '缺少安全头',
                        'detail': f'{header} 未设置'
                    })

            # 技术栈泄露
            if 'X-Powered-By' in headers:
                self.findings.append({
                    'severity': 'MEDIUM', 'type': '技术栈泄露',
                    'detail': f"X-Powered-By: {headers['X-Powered-By']}"
                })
            if 'Server' in headers:
                self.findings.append({
                    'severity': 'INFO', 'type': 'Server信息',
                    'detail': f"Server: {headers['Server']}"
                })

            return resp
        except Exception as e:
            print(f"  [!] 连接失败: {e}")
            return None

    def scan_sensitive_files(self):
        """扫描敏感文件"""
        sensitive_paths = [
            ('.env', 'HIGH', '环境配置文件'),
            ('.git/HEAD', 'HIGH', 'Git仓库泄露'),
            ('robots.txt', 'LOW', 'Robots文件'),
            ('.htaccess', 'LOW', 'Apache配置'),
            ('wp-config.php', 'HIGH', 'WordPress配置'),
            ('admin/', 'MEDIUM', '管理后台'),
            ('phpmyadmin/', 'MEDIUM', 'phpMyAdmin'),
            ('.DS_Store', 'LOW', 'Mac目录文件'),
            ('backup.sql', 'HIGH', '数据库备份'),
            ('sitemap.xml', 'LOW', '站点地图'),
        ]

        for path, severity, desc in sensitive_paths:
            url = f"{self.target}/{path}"
            try:
                resp = requests.get(url, timeout=self.timeout, verify=False,
                                    allow_redirects=False,
                                    headers={'User-Agent': 'SecurityScanner/1.0'})
                if resp.status_code == 200 and len(resp.text) > 50:
                    self.findings.append({
                        'severity': severity, 'type': '敏感文件',
                        'detail': f'{path} ({desc}) - HTTP {resp.status_code}'
                    })
            except:
                pass

    def run(self):
        """执行 Web 扫描"""
        print(f"\n  [模块4] Web 漏洞扫描")
        print(f"  {'-' * 40}")
        print(f"  目标: {self.target}")

        if not HAS_REQUESTS:
            print("  [!] 需要安装 requests: pip install requests")
            return {'findings': []}

        import requests as req
        req.packages.urllib3.disable_warnings()

        self.findings = []
        start = time.time()

        resp = self.check_headers()
        if resp:
            print(f"  状态码: {resp.status_code}")
            self.scan_sensitive_files()

        elapsed = time.time() - start

        # 输出发现
        for f in self.findings:
            icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}
            print(f"  {icon.get(f['severity'], '?')} [{f['severity']}] {f['type']}: {f['detail']}")

        print(f"\n  扫描完成: {len(self.findings)} 个发现, 耗时 {elapsed:.1f}s")

        return {
            'target': self.target,
            'findings': self.findings,
            'scan_time': elapsed
        }


# ============================================================
#  模块 5：日志分析器
# ============================================================

class LogAnalyzer:
    """日志分析器（精简版 - auth.log 分析）"""

    def __init__(self, logfile):
        self.logfile = logfile
        self.stats = {
            'total': 0, 'failed': 0, 'success': 0,
            'ips': {}, 'users': {}
        }

    def run(self):
        """分析 auth.log"""
        print(f"\n  [模块5] 日志分析")
        print(f"  {'-' * 40}")
        print(f"  文件: {self.logfile}")

        import re
        failed_pattern = re.compile(
            r'Failed password for (\S+) from (\S+)')
        success_pattern = re.compile(
            r'Accepted \S+ for (\S+) from (\S+)')

        try:
            with open(self.logfile, 'r', errors='ignore') as f:
                for line in f:
                    self.stats['total'] += 1

                    m = failed_pattern.search(line)
                    if m:
                        self.stats['failed'] += 1
                        user, ip = m.group(1), m.group(2)
                        self.stats['ips'][ip] = self.stats['ips'].get(ip, 0) + 1
                        self.stats['users'][user] = self.stats['users'].get(user, 0) + 1
                        continue

                    m = success_pattern.search(line)
                    if m:
                        self.stats['success'] += 1
        except FileNotFoundError:
            print(f"  [!] 文件不存在: {self.logfile}")
            return {}
        except Exception as e:
            print(f"  [!] 读取错误: {e}")
            return {}

        print(f"  总行数: {self.stats['total']}")
        print(f"  登录失败: {self.stats['failed']}")
        print(f"  登录成功: {self.stats['success']}")

        if self.stats['ips']:
            print(f"\n  TOP 攻击IP:")
            for ip, count in sorted(self.stats['ips'].items(),
                                    key=lambda x: -x[1])[:5]:
                print(f"    {ip:18s} {count:5d} 次")
                if count >= 10:
                    print(f"    🔴 疑似暴力破解!")

        return self.stats


# ============================================================
#  模块 6：简易 IDS
# ============================================================

class SimpleIDS:
    """简易入侵检测（精简版 - 基于 PCAP 分析）"""

    def __init__(self, pcap_file=None):
        self.pcap_file = pcap_file
        self.alerts = []

    def analyze_pcap(self):
        """分析 PCAP 文件"""
        if not HAS_SCAPY:
            print("  [!] 需要安装 scapy: pip install scapy")
            return []

        from scapy.all import rdpcap

        print(f"\n  [模块6] 入侵检测 (PCAP分析)")
        print(f"  {'-' * 40}")
        print(f"  文件: {self.pcap_file}")

        try:
            packets = rdpcap(self.pcap_file)
        except Exception as e:
            print(f"  [!] 读取失败: {e}")
            return []

        syn_count = {}  # src -> ports
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                if pkt[TCP].flags == 0x02:  # SYN
                    src = pkt[IP].src
                    port = pkt[TCP].dport
                    if src not in syn_count:
                        syn_count[src] = set()
                    syn_count[src].add(port)

        for src, ports in syn_count.items():
            if len(ports) > 10:
                alert = {
                    'type': '端口扫描', 'severity': 'HIGH',
                    'src': src, 'detail': f'扫描了 {len(ports)} 个端口'
                }
                self.alerts.append(alert)
                print(f"  🔴 {src} -> {alert['detail']}")

        print(f"\n  分析完成: {len(packets)} 个包, {len(self.alerts)} 条告警")
        return self.alerts


# ============================================================
#  综合报告生成
# ============================================================

class SecurityReport:
    """安全评估报告"""

    def __init__(self, target):
        self.target = target
        self.start_time = datetime.now()
        self.sections = {}

    def add_section(self, name, data):
        self.sections[name] = data

    def generate(self):
        """生成综合报告"""
        end_time = datetime.now()
        elapsed = (end_time - self.start_time).total_seconds()

        print(f"\n{'=' * 60}")
        print(f"  📋 综合安全评估报告")
        print(f"  {'=' * 60}")
        print(f"  目标: {self.target}")
        print(f"  时间: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  耗时: {elapsed:.1f} 秒")
        print(f"  模块: {len(self.sections)} 个")

        # 风险统计
        risk_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

        # 汇总所有发现
        all_findings = []
        for section_name, data in self.sections.items():
            if isinstance(data, dict):
                findings = data.get('findings', [])
                for f in findings:
                    sev = f.get('severity', 'INFO')
                    risk_count[sev] = risk_count.get(sev, 0) + 1
                    all_findings.append({**f, 'source': section_name})

        print(f"\n  {'=' * 50}")
        print(f"  风险总览")
        print(f"  {'=' * 50}")
        icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = risk_count.get(sev, 0)
            bar = '█' * min(count, 20)
            print(f"  {icons.get(sev, '?')} {sev:10s} {count:3d} {bar}")

        total_risks = sum(risk_count.values())
        print(f"\n  总发现: {total_risks}")

        # 风险评分
        score = 100
        score -= risk_count.get('CRITICAL', 0) * 20
        score -= risk_count.get('HIGH', 0) * 10
        score -= risk_count.get('MEDIUM', 0) * 5
        score -= risk_count.get('LOW', 0) * 2
        score = max(0, score)

        if score >= 80:
            grade = 'A (安全)'
        elif score >= 60:
            grade = 'B (较好)'
        elif score >= 40:
            grade = 'C (一般)'
        elif score >= 20:
            grade = 'D (较差)'
        else:
            grade = 'F (危险)'

        print(f"\n  安全评分: {score}/100  等级: {grade}")

        # 保存 JSON 报告
        report = {
            'target': self.target,
            'time': self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'elapsed': elapsed,
            'risk_summary': risk_count,
            'total_findings': total_risks,
            'score': score,
            'grade': grade,
            'sections': {k: v for k, v in self.sections.items()},
            'all_findings': all_findings,
        }

        report_file = f"security_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        print(f"\n  报告已保存: {report_file}")
        print(f"{'=' * 60}")

        return report


# ============================================================
#  主程序：交互式菜单
# ============================================================

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║           🛡️  安全工具集成平台 v1 - Day7 实战            ║
║           作者: YURM | 日期: 2026-05-23                ║
╠══════════════════════════════════════════════════════════╣
║  [1] 端口扫描器 (Day1)                                   ║
║  [2] SSH 批量管理 (Day2)                                  ║
║  [3] 流量分析器 (Day3)                                    ║
║  [4] Web 漏洞扫描器 (Day4)                                ║
║  [5] 日志分析系统 (Day5)                                   ║
║  [6] 入侵检测系统 (Day6)                                   ║
║  [7] 🔥 一键综合安全评估                                   ║
║  [0] 退出                                                 ║
╚══════════════════════════════════════════════════════════╝
    """)


def run_full_scan(target):
    """一键综合安全评估"""
    report = SecurityReport(target)

    print(f"\n{'=' * 60}")
    print(f"  🔥 一键综合安全评估")
    print(f"  目标: {target}")
    print(f"  开始时间: {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'=' * 60}")

    # 模块1: 端口扫描
    scanner = PortScanner(target)
    port_result = scanner.run()
    report.add_section('端口扫描', port_result)

    # 模块4: Web 漏洞扫描（如果有 HTTP 端口）
    http_ports = [p for p in port_result.get('open_ports', [])
                  if p in (80, 443, 8080, 8443)]
    if http_ports:
        for port in http_ports:
            scheme = 'https' if port in (443, 8443) else 'http'
            web_target = f"{scheme}://{target}:{port}" if port not in (80, 443) else f"{scheme}://{target}"
            web_scanner = WebScanner(web_target)
            web_result = web_scanner.run()
            report.add_section(f'Web扫描({port})', web_result)

    # 生成报告
    report.generate()


def main():
    parser = argparse.ArgumentParser(description='Day7: 安全工具集成平台')
    parser.add_argument('--target', '-t', help='目标 IP/域名')
    parser.add_argument('--auto', '-a', action='store_true', help='自动模式（一键评估）')
    args = parser.parse_args()

    # 自动模式
    if args.auto and args.target:
        print_banner()
        run_full_scan(args.target)
        return

    # 交互模式
    while True:
        print_banner()

        try:
            choice = input("  请选择功能 [0-7]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  再见！")
            break

        if choice == '0':
            print("\n  再见！")
            break

        elif choice == '1':
            target = args.target or input("  输入目标 IP: ").strip()
            scanner = PortScanner(target)
            scanner.run()

        elif choice == '2':
            if not HAS_PARAMIKO:
                print("  [!] 需要安装 paramiko: pip install paramiko")
                continue
            host = input("  输入主机 IP: ").strip()
            user = input("  用户名 [root]: ").strip() or 'root'
            pwd = input("  密码: ").strip()
            cmd = input("  命令: ").strip()
            manager = SSHManager([(host, 22)], username=user, password=pwd)
            manager.run_command(cmd)

        elif choice == '3':
            pcap = input("  输入 PCAP 文件路径: ").strip()
            if os.path.exists(pcap):
                analyzer = SimpleIDS(pcap)
                analyzer.analyze_pcap()
            else:
                print(f"  [!] 文件不存在: {pcap}")

        elif choice == '4':
            target = args.target or input("  输入目标 URL: ").strip()
            if not target.startswith('http'):
                target = 'http://' + target
            web_scanner = WebScanner(target)
            web_scanner.run()

        elif choice == '5':
            logfile = input("  输入日志文件路径: ").strip()
            analyzer = LogAnalyzer(logfile)
            analyzer.run()

        elif choice == '6':
            pcap = input("  输入 PCAP 文件路径: ").strip()
            if os.path.exists(pcap):
                ids = SimpleIDS(pcap)
                ids.analyze_pcap()
            else:
                print(f"  [!] 文件不存在: {pcap}")

        elif choice == '7':
            target = args.target or input("  输入目标 IP/域名: ").strip()
            run_full_scan(target)

        else:
            print("  [!] 无效选择")

        input("\n  按 Enter 继续...")


if __name__ == "__main__":
    main()
