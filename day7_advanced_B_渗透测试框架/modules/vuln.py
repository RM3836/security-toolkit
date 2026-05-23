# -*- coding: utf-8 -*-
"""
渗透测试框架 - 漏洞检测模块
作者: YURM
日期: 2026-05-23

功能:
  - SQL 注入检测 (错误型、时间型)
  - XSS 反射测试
  - 目录遍历测试
  - 命令注入测试
  - SSL/TLS 弱点检查
"""

import socket
import ssl
import time
import re
import hashlib
from urllib.parse import urljoin, quote

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


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


class VulnModule:
    """
    漏洞检测模块

    对目标进行自动化漏洞扫描, 包括 SQL 注入、XSS、
    目录遍历、命令注入和 SSL/TLS 安全检测。
    """

    # SQL 注入 payload 和对应的错误特征
    SQLI_PAYLOADS = [
        ("'", ["sql syntax", "mysql", "sqlite", "postgresql", "ora-",
               "microsoft", "unclosed quotation", "unterminated",
               "syntax error", "unexpected end", "you have an error"]),
        ("' OR '1'='1", ["sql syntax", "mysql", "error"]),
        ("1' AND '1'='1", []),
        ("1' AND '1'='2", []),
        ("' UNION SELECT NULL--", ["sql syntax", "union", "column"]),
        ("1; DROP TABLE--", ["sql syntax", "drop", "error"]),
    ]

    # 时间型 SQL 注入 payload
    SQLI_TIME_PAYLOADS = [
        ("' OR SLEEP(3)--", 3),
        ("'; WAITFOR DELAY '0:0:3'--", 3),
        ("' AND BENCHMARK(10000000,SHA1('test'))--", 2),
    ]

    # XSS 测试 payload
    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
    ]

    # 目录遍历 payload
    TRAVERSAL_PAYLOADS = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc/passwd',
        '..%c0%af..%c0%af..%c0%afetc/passwd',
    ]

    # 命令注入 payload
    CMD_INJECTION_PAYLOADS = [
        ('; id', ['uid=', 'gid=']),
        ('| id', ['uid=', 'gid=']),
        ('`id`', ['uid=', 'gid=']),
        ('$(id)', ['uid=', 'gid=']),
        ('; cat /etc/passwd', ['root:', '/bin/']),
        ('| ping -c 3 127.0.0.1', ['ping', 'ttl']),
    ]

    def __init__(self, target: str, open_ports: list = None):
        """
        初始化漏洞检测模块

        Args:
            target: 目标域名或 IP
            open_ports: 开放端口列表 (来自扫描模块)
        """
        self.target = target.replace('http://', '').replace('https://', '').strip('/')
        self.open_ports = open_ports or []
        self.results = {
            'target': self.target,
            'vulnerabilities': [],
            'ssl_info': {},
        }

    def _print_banner(self):
        """打印模块横幅"""
        banner = f"""
{Colors.YELLOW}{'='*60}
  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
  ██║   ██║██║   ██║██║     █████╗  ██║
  ██║   ██║██║   ██║██║     ██╔██╗ ██║
  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝
  漏洞检测模块 (Vulnerability Scanner)
{'='*60}{Colors.END}"""
        print(banner)

    def _add_vuln(self, vuln_type: str, severity: str, description: str,
                  evidence: str = '', remediation: str = ''):
        """
        添加漏洞发现

        Args:
            vuln_type: 漏洞类型
            severity: 严重程度 (Critical/High/Medium/Low/Info)
            description: 描述
            evidence: 证据
            remediation: 修复建议
        """
        vuln = {
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'evidence': evidence[:500],
            'remediation': remediation,
        }
        self.results['vulnerabilities'].append(vuln)

        severity_colors = {
            'Critical': Colors.RED + Colors.BOLD,
            'High': Colors.RED,
            'Medium': Colors.YELLOW,
            'Low': Colors.CYAN,
            'Info': Colors.BLUE,
        }
        color = severity_colors.get(severity, Colors.END)
        print(f"  {color}[!] [{severity}] {vuln_type}: {description}{Colors.END}")
        if evidence:
            print(f"      证据: {evidence[:100]}")

    def sqli_detection(self) -> list:
        """
        SQL 注入检测

        测试 URL 参数是否存在 SQL 注入漏洞。
        支持错误型和时间型检测。

        Returns:
            发现的 SQL 注入漏洞列表
        """
        print(f"\n{Colors.YELLOW}[*] SQL 注入检测{Colors.END}")

        if not HAS_REQUESTS:
            print(f"  {Colors.RED}[-] requests 库未安装{Colors.END}")
            return []

        vulns = []
        base_urls = [
            f"https://{self.target}/",
            f"http://{self.target}/",
        ]

        test_params = ['id', 'page', 'cat', 'search', 'q', 'user', 'item', 'product']

        for base_url in base_urls:
            try:
                resp = requests.get(base_url, timeout=5, verify=False)
                if resp.status_code >= 400:
                    continue

                # 测试 GET 参数
                for param in test_params:
                    for payload, error_signs in self.SQLI_PAYLOADS:
                        url = f"{base_url}?{param}={quote(payload)}"
                        try:
                            start = time.time()
                            r = requests.get(url, timeout=10, verify=False)
                            elapsed = time.time() - start

                            # 错误型检测
                            body_lower = r.text.lower()
                            for sign in error_signs:
                                if sign in body_lower:
                                    self._add_vuln(
                                        'SQL 注入 (错误型)', 'High',
                                        f'参数 {param} 存在 SQL 注入',
                                        f'Payload: {payload}, 错误特征: {sign}',
                                        '使用参数化查询, 输入验证, WAF'
                                    )
                                    vulns.append({
                                        'type': 'sqli_error', 'param': param,
                                        'payload': payload, 'url': base_url
                                    })
                                    break

                        except Exception:
                            continue

                        # 时间型检测
                        for payload, delay in self.SQLI_TIME_PAYLOADS:
                            url = f"{base_url}?{param}={quote(payload)}"
                            try:
                                start = time.time()
                                r = requests.get(url, timeout=delay + 5, verify=False)
                                elapsed = time.time() - start
                                if elapsed >= delay:
                                    self._add_vuln(
                                        'SQL 注入 (时间型)', 'High',
                                        f'参数 {param} 可能存在时间型 SQL 注入',
                                        f'Payload: {payload}, 延迟: {elapsed:.1f}s',
                                        '使用参数化查询, 输入验证'
                                    )
                                    vulns.append({
                                        'type': 'sqli_time', 'param': param,
                                        'payload': payload, 'url': base_url
                                    })
                            except Exception:
                                continue

                break  # 有一个 scheme 成功就停止
            except Exception:
                continue

        if not vulns:
            print(f"  {Colors.GREEN}[+] 未发现 SQL 注入漏洞{Colors.END}")

        return vulns

    def xss_detection(self) -> list:
        """
        XSS 反射检测

        测试 URL 参数是否存在反射型 XSS。

        Returns:
            发现的 XSS 漏洞列表
        """
        print(f"\n{Colors.YELLOW}[*] XSS 反射检测{Colors.END}")

        if not HAS_REQUESTS:
            return []

        vulns = []
        test_params = ['q', 'search', 'query', 'keyword', 'name', 'input', 'msg']

        for scheme in ['https', 'http']:
            base_url = f"{scheme}://{self.target}"
            try:
                requests.get(base_url, timeout=5, verify=False)
            except Exception:
                continue

            for param in test_params:
                for payload in self.XSS_PAYLOADS:
                    url = f"{base_url}?{param}={quote(payload)}"
                    try:
                        r = requests.get(url, timeout=5, verify=False)
                        if payload in r.text:
                            self._add_vuln(
                                '反射型 XSS', 'High',
                                f'参数 {param} 存在 XSS 反射',
                                f'Payload: {payload}',
                                '输出编码, CSP 头部, 输入验证'
                            )
                            vulns.append({
                                'type': 'xss_reflected', 'param': param,
                                'payload': payload, 'url': base_url
                            })
                            break
                    except Exception:
                        continue
            break

        if not vulns:
            print(f"  {Colors.GREEN}[+] 未发现 XSS 漏洞{Colors.END}")

        return vulns

    def directory_traversal(self) -> list:
        """
        目录遍历检测

        测试 URL 参数是否存在目录遍历漏洞。

        Returns:
            发现的目录遍历漏洞列表
        """
        print(f"\n{Colors.YELLOW}[*] 目录遍历检测{Colors.END}")

        if not HAS_REQUESTS:
            return []

        vulns = []
        test_params = ['file', 'path', 'page', 'include', 'dir', 'document', 'template']

        linux_signs = ['root:', '/bin/bash', '/sbin/nologin', 'daemon:']
        windows_signs = ['[boot loader]', '[fonts]', '[extensions]']

        for scheme in ['https', 'http']:
            base_url = f"{scheme}://{self.target}"
            try:
                requests.get(base_url, timeout=5, verify=False)
            except Exception:
                continue

            for param in test_params:
                for payload in self.TRAVERSAL_PAYLOADS:
                    url = f"{base_url}?{param}={quote(payload)}"
                    try:
                        r = requests.get(url, timeout=5, verify=False)
                        body = r.text
                        for sign in linux_signs + windows_signs:
                            if sign in body:
                                os_type = 'Linux' if sign in linux_signs else 'Windows'
                                self._add_vuln(
                                    '目录遍历', 'Critical',
                                    f'参数 {param} 存在目录遍历 ({os_type})',
                                    f'Payload: {payload}, 特征: {sign}',
                                    '输入验证, chroot, 最小权限原则'
                                )
                                vulns.append({
                                    'type': 'traversal', 'param': param,
                                    'payload': payload, 'os': os_type
                                })
                                break
                        if vulns:
                            break
                    except Exception:
                        continue
                if vulns:
                    break
            break

        if not vulns:
            print(f"  {Colors.GREEN}[+] 未发现目录遍历漏洞{Colors.END}")

        return vulns

    def command_injection(self) -> list:
        """
        命令注入检测

        测试 URL 参数是否存在操作系统命令注入。

        Returns:
            发现的命令注入漏洞列表
        """
        print(f"\n{Colors.YELLOW}[*] 命令注入检测{Colors.END}")

        if not HAS_REQUESTS:
            return []

        vulns = []
        test_params = ['cmd', 'exec', 'command', 'ping', 'host', 'ip', 'target']

        for scheme in ['https', 'http']:
            base_url = f"{scheme}://{self.target}"
            try:
                requests.get(base_url, timeout=5, verify=False)
            except Exception:
                continue

            for param in test_params:
                for payload, signs in self.CMD_INJECTION_PAYLOADS:
                    url = f"{base_url}?{param}={quote(payload)}"
                    try:
                        r = requests.get(url, timeout=10, verify=False)
                        body = r.text.lower()
                        for sign in signs:
                            if sign in body:
                                self._add_vuln(
                                    '命令注入', 'Critical',
                                    f'参数 {param} 存在命令注入',
                                    f'Payload: {payload}',
                                    '避免调用系统命令, 输入白名单验证'
                                )
                                vulns.append({
                                    'type': 'cmd_injection', 'param': param,
                                    'payload': payload
                                })
                                break
                        if vulns:
                            break
                    except Exception:
                        continue
                if vulns:
                    break
            break

        if not vulns:
            print(f"  {Colors.GREEN}[+] 未发现命令注入漏洞{Colors.END}")

        return vulns

    def ssl_tls_check(self) -> dict:
        """
        SSL/TLS 安全检查

        检查目标的 SSL/TLS 配置, 包括证书信息、协议版本和密码套件。

        Returns:
            SSL/TLS 检查结果
        """
        print(f"\n{Colors.YELLOW}[*] SSL/TLS 安全检查{Colors.END}")

        ssl_info = {
            'has_ssl': False,
            'cert_info': {},
            'protocols': {},
            'issues': [],
        }

        # 检查 443 端口是否开放
        has_443 = any(p.get('port') == 443 for p in self.open_ports)
        if not has_443:
            # 快速检查
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target, 443))
                sock.close()
                has_443 = True
            except Exception:
                pass

        if not has_443:
            print(f"  {Colors.YELLOW}[!] 443 端口未开放, 跳过 SSL 检查{Colors.END}")
            self.results['ssl_info'] = ssl_info
            return ssl_info

        ssl_info['has_ssl'] = True

        # 证书信息
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    ssl_info['cert_info'] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version', ''),
                        'notBefore': cert.get('notBefore', ''),
                        'notAfter': cert.get('notAfter', ''),
                        'serialNumber': cert.get('serialNumber', ''),
                        'san': [entry[1] for entry in cert.get('subjectAltName', [])],
                    }
                    ssl_info['tls_version'] = version
                    ssl_info['cipher'] = cipher

                    print(f"  {Colors.GREEN}[+] TLS 版本: {version}{Colors.END}")
                    print(f"  {Colors.GREEN}[+] 密码套件: {cipher[0]} ({cipher[1]} bits){Colors.END}")
                    print(f"  {Colors.GREEN}[+] 证书颁发者: {ssl_info['cert_info']['issuer'].get('organizationName', '未知')}{Colors.END}")
                    print(f"  {Colors.GREEN}[+] 有效期至: {ssl_info['cert_info']['notAfter']}{Colors.END}")

                    # 检查 TLS 版本
                    if version in ['TLSv1', 'TLSv1.1']:
                        self._add_vuln(
                            '弱 TLS 版本', 'Medium',
                            f'服务器使用 {version}, 应升级到 TLS 1.2+',
                            f'当前版本: {version}',
                            '禁用 TLS 1.0/1.1, 仅启用 TLS 1.2 和 1.3'
                        )
                        ssl_info['issues'].append('weak_tls_version')

        except ssl.SSLCertVerificationError as e:
            print(f"  {Colors.RED}[!] 证书验证失败: {e}{Colors.END}")
            self._add_vuln(
                'SSL 证书无效', 'High',
                'SSL 证书验证失败',
                str(e),
                '使用有效的 CA 签名证书'
            )
        except Exception as e:
            print(f"  {Colors.RED}[!] SSL 检查失败: {e}{Colors.END}")

        # 测试弱密码套件
        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon']
        try:
            context_all = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context_all.check_hostname = False
            context_all.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with context_all.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        for weak in weak_ciphers:
                            if weak in cipher_name.upper():
                                self._add_vuln(
                                    '弱密码套件', 'Medium',
                                    f'使用了弱密码套件: {cipher_name}',
                                    f'包含: {weak}',
                                    '禁用弱密码套件, 仅使用 AES-GCM 等强密码'
                                )
                                break
        except Exception:
            pass

        self.results['ssl_info'] = ssl_info
        return ssl_info

    def run(self) -> dict:
        """
        执行完整的漏洞检测流程

        Returns:
            所有检测结果的汇总字典
        """
        self._print_banner()
        print(f"\n{Colors.BOLD}[*] 目标: {self.target}{Colors.END}")
        print(f"{Colors.BOLD}[*] 开始漏洞检测...{Colors.END}")

        start_time = time.time()

        # 1. SQL 注入检测
        self.sqli_detection()

        # 2. XSS 检测
        self.xss_detection()

        # 3. 目录遍历检测
        self.directory_traversal()

        # 4. 命令注入检测
        self.command_injection()

        # 5. SSL/TLS 检查
        self.ssl_tls_check()

        elapsed = time.time() - start_time

        # 漏洞统计
        vulns = self.results['vulnerabilities']
        severity_count = {}
        for v in vulns:
            sev = v['severity']
            severity_count[sev] = severity_count.get(sev, 0) + 1

        print(f"\n{Colors.BOLD}{'='*50}")
        print(f"  漏洞检测摘要")
        print(f"{'='*50}{Colors.END}")
        print(f"  总发现: {len(vulns)} 个漏洞")
        for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = severity_count.get(sev, 0)
            if count > 0:
                print(f"  {sev}: {count}")
        print(f"  耗时: {elapsed:.1f}s")
        print(f"{Colors.BOLD}{'='*50}{Colors.END}")

        return self.results


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        module = VulnModule(sys.argv[1])
        module.run()
    else:
        print("用法: python -m modules.vuln <目标域名>")
