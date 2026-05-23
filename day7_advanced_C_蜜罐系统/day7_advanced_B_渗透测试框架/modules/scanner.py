# -*- coding: utf-8 -*-
"""
渗透测试框架 - 端口与服务扫描模块
作者: YURM
日期: 2026-05-23

功能:
  - TCP 连接扫描 (多线程, Top 1000 端口)
  - 服务 Banner 抓取
  - OS 指纹识别 (基于 TTL)
"""

import socket
import threading
import time
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed


class Colors:
    """终端颜色定义"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


# 常见端口及服务映射
COMMON_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
    69: 'TFTP', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3',
    111: 'RPCbind', 119: 'NNTP', 123: 'NTP', 135: 'MSRPC',
    137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
    143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap', 389: 'LDAP',
    443: 'HTTPS', 445: 'SMB', 464: 'Kerberos', 465: 'SMTPS',
    500: 'ISAKMP', 514: 'Syslog', 515: 'LPD', 520: 'RIP',
    523: 'IBM-DB2', 554: 'RTSP', 587: 'SMTP-Sub', 623: 'IPMI',
    636: 'LDAPS', 873: 'Rsync', 902: 'VMware', 993: 'IMAPS',
    995: 'POP3S', 1080: 'SOCKS', 1099: 'RMI', 1433: 'MSSQL',
    1434: 'MSSQL-Mon', 1521: 'Oracle', 1723: 'PPTP', 1883: 'MQTT',
    2049: 'NFS', 2181: 'ZooKeeper', 2375: 'Docker', 2376: 'Docker-TLS',
    3000: 'Grafana', 3306: 'MySQL', 3389: 'RDP', 4443: 'HTTPS-Alt',
    4848: 'GlassFish', 5000: 'Docker-Reg', 5432: 'PostgreSQL',
    5672: 'RabbitMQ', 5900: 'VNC', 5984: 'CouchDB', 6379: 'Redis',
    6443: 'K8s-API', 6660: 'IRC', 6667: 'IRC', 7001: 'WebLogic',
    8000: 'HTTP-Alt', 8001: 'HTTP-Alt', 8008: 'HTTP-Alt',
    8009: 'AJP', 8080: 'HTTP-Proxy', 8081: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 8834: 'Nessus', 8888: 'HTTP-Alt',
    9090: 'Prometheus', 9200: 'Elasticsearch', 9300: 'ES-Transport',
    9418: 'Git', 9999: 'HTTP-Alt', 10000: 'Webmin',
    11211: 'Memcached', 27017: 'MongoDB',
}


class ScannerModule:
    """
    端口与服务扫描模块

    执行 TCP 连接扫描、Banner 抓取和 OS 指纹识别。
    使用多线程加速扫描过程。
    """

    def __init__(self, target: str, ports: list = None, threads: int = 100, timeout: float = 1.0):
        """
        初始化扫描模块

        Args:
            target: 目标 IP 或域名
            ports: 要扫描的端口列表, 默认为 Top 1000
            threads: 并发线程数
            timeout: 连接超时(秒)
        """
        self.target = target
        self.ports = ports or sorted(COMMON_PORTS.keys())
        self.threads = threads
        self.timeout = timeout
        self.results = {
            'target': target,
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'os_guess': '未知',
            'scan_time': 0,
        }
        self._lock = threading.Lock()

    def _print_banner(self):
        """打印模块横幅"""
        banner = f"""
{Colors.BLUE}{'='*60}
  ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ███████╗██║     ███████║██╔██╗ ██║
  ╚════██║██║     ██╔══██║██║╚██╗██║
  ███████║╚██████╗██║  ██║██║ ╚████║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
  端口与服务扫描模块 (Port Scanner)
{'='*60}{Colors.END}"""
        print(banner)

    def tcp_connect_scan(self) -> list:
        """
        TCP 连接扫描

        使用多线程对目标端口进行 TCP 连接测试。
        对每个开放端口尝试抓取服务 Banner。

        Returns:
            开放端口列表
        """
        print(f"\n{Colors.BLUE}[*] TCP 连接扫描: {self.target}{Colors.END}")
        print(f"  {Colors.CYAN}[*] 扫描端口数: {len(self.ports)}, 线程数: {self.threads}{Colors.END}")

        open_ports = []
        closed_count = 0
        filtered_count = 0
        total = len(self.ports)
        done = [0]

        def scan_port(port):
            """扫描单个端口"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    banner = self._grab_banner(sock, port)
                    service = COMMON_PORTS.get(port, '未知')
                    with self._lock:
                        port_info = {
                            'port': port,
                            'state': 'open',
                            'service': service,
                            'banner': banner,
                        }
                        open_ports.append(port_info)
                        color = Colors.GREEN
                        banner_str = f" | {banner[:50]}" if banner else ""
                        print(f"  {color}[+] {port}/tcp 开放  {service:<15}{banner_str}{Colors.END}")
                sock.close()
            except socket.timeout:
                with self._lock:
                    pass  # filtered
            except ConnectionRefusedError:
                pass  # closed
            except Exception:
                pass
            finally:
                with self._lock:
                    done[0] += 1
                    if done[0] % 100 == 0 or done[0] == total:
                        pct = done[0] / total * 100
                        print(f"\r  {Colors.CYAN}[*] 扫描进度: {pct:.0f}% ({done[0]}/{total}){Colors.END}",
                              end='', flush=True)

        start = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(scan_port, p): p for p in self.ports}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

        elapsed = time.time() - start
        print(f"\n\n  {Colors.GREEN}[+] 扫描完成: {len(open_ports)} 个开放端口 (耗时: {elapsed:.1f}s){Colors.END}")

        # 按端口号排序
        open_ports.sort(key=lambda x: x['port'])
        self.results['open_ports'] = open_ports
        self.results['scan_time'] = elapsed
        return open_ports

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        抓取服务 Banner

        Args:
            sock: 已连接的 socket
            port: 端口号

        Returns:
            Banner 字符串
        """
        try:
            sock.settimeout(2)
            # HTTP 端口发送请求
            if port in [80, 8080, 8000, 8001, 8443, 443, 8888]:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " +
                          self.target.encode() + b"\r\n\r\n")
            # SMTP
            elif port == 25:
                pass  # SMTP 会主动发送 banner
            # FTP
            elif port == 21:
                pass  # FTP 会主动发送 banner
            # SSH
            elif port == 22:
                pass  # SSH 会主动发送 banner
            else:
                sock.send(b"\r\n")

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200]
        except Exception:
            return ""

    def os_fingerprint(self) -> str:
        """
        OS 指纹识别 (基于 TTL)

        通过 TCP 连接的初始 TTL 值推断操作系统类型。

        Returns:
            操作系统猜测结果
        """
        print(f"\n{Colors.BLUE}[*] OS 指纹识别: {self.target}{Colors.END}")

        os_guess = '未知'
        ttl_value = None

        try:
            # 通过 socket 连接获取 TTL
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)

            # 使用 IP_HDRINCL 来获取 TTL
            # 简化方案: 通过 ICMP TTL 推断
            import subprocess
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', self.target],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # 解析 TTL 值
                import re
                ttl_match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
                if ttl_match:
                    ttl_value = int(ttl_match.group(1))

            sock.close()
        except Exception as e:
            print(f"  {Colors.YELLOW}[!] OS 指纹识别失败: {e}{Colors.END}")

        if ttl_value:
            print(f"  {Colors.CYAN}[*] 检测到 TTL: {ttl_value}{Colors.END}")

            # TTL 推断操作系统
            if ttl_value <= 64:
                os_guess = 'Linux/Unix (TTL<=64)'
                icon = '🐧'
            elif ttl_value <= 128:
                os_guess = 'Windows (TTL<=128)'
                icon = '🪟'
            elif ttl_value <= 255:
                os_guess = 'Solaris/AIX/网络设备 (TTL<=255)'
                icon = '🔧'
            else:
                os_guess = '未知操作系统'

            print(f"  {Colors.GREEN}[+] 操作系统猜测: {icon} {os_guess}{Colors.END}")
        else:
            print(f"  {Colors.YELLOW}[!] 无法获取 TTL, OS 识别失败{Colors.END}")

        # 额外: 通过开放端口推断
        if self.results['open_ports']:
            ports = {p['port'] for p in self.results['open_ports']}
            if 3389 in ports and 445 in ports:
                os_guess += ' (高概率 Windows)'
                print(f"  {Colors.GREEN}[+] 端口特征: 检测到 3389(RDP) + 445(SMB) -> 高概率 Windows{Colors.END}")
            elif 22 in ports and 3389 not in ports:
                print(f"  {Colors.GREEN}[+] 端口特征: 检测到 22(SSH), 无 RDP -> 可能为 Linux{Colors.END}")

        self.results['os_guess'] = os_guess
        return os_guess

    def run(self) -> dict:
        """
        执行完整的端口扫描流程

        Returns:
            扫描结果字典
        """
        self._print_banner()
        print(f"\n{Colors.BOLD}[*] 目标: {self.target}{Colors.END}")
        print(f"{Colors.BOLD}[*] 开始端口扫描...{Colors.END}")

        start_time = time.time()

        # 1. TCP 连接扫描
        self.tcp_connect_scan()

        # 2. OS 指纹识别
        self.os_fingerprint()

        total_time = time.time() - start_time

        # 打印摘要
        print(f"\n{Colors.BOLD}{'='*50}")
        print(f"  扫描摘要")
        print(f"{'='*50}{Colors.END}")
        print(f"  目标: {self.target}")
        print(f"  开放端口: {len(self.results['open_ports'])}")
        print(f"  OS 推断: {self.results['os_guess']}")
        print(f"  总耗时: {total_time:.1f}s")
        print(f"{Colors.BOLD}{'='*50}{Colors.END}")

        return self.results


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        scanner = ScannerModule(sys.argv[1])
        scanner.run()
    else:
        print("用法: python -m modules.scanner <目标IP>")
