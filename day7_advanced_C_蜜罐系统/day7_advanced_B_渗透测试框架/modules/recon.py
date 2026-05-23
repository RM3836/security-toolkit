# -*- coding: utf-8 -*-
"""
渗透测试框架 - 信息收集模块
作者: YURM
日期: 2026-05-23

功能:
  - DNS 记录查询 (A, MX, NS, TXT)
  - WHOIS 类信息收集 (HTTP 头部, 服务器技术)
  - 子域名枚举
  - robots.txt / sitemap.xml 解析
"""

import socket
import threading
import time
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

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


class ReconModule:
    """
    信息收集模块

    执行目标的基础信息收集, 包括 DNS 解析、HTTP 头部分析、
    子域名枚举和敏感文件探测。
    """

    def __init__(self, target: str, output_dir: str = "reports"):
        """
        初始化信息收集模块

        Args:
            target: 目标域名或 IP
            output_dir: 输出目录
        """
        self.target = target.replace('http://', '').replace('https://', '').strip('/')
        self.output_dir = output_dir
        self.results = {
            'target': self.target,
            'dns_records': {},
            'http_info': {},
            'subdomains': [],
            'sensitive_files': {},
        }

    def _print_banner(self):
        """打印模块横幅"""
        banner = f"""
{Colors.CYAN}{'='*60}
  ██╗███╗   ██╗███████╗ ██████╗
  ██║████╗  ██║██╔════╝██╔═══██╗
  ██║██╔██╗ ██║█████╗  ██║   ██║
  ██║██║╚██╗██║██╔══╝  ██║   ██║
  ██║██║ ╚████║██║     ╚██████╔╝
  ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝
  信息收集模块 (Reconnaissance)
{'='*60}{Colors.END}"""
        print(banner)

    def dns_lookup(self) -> dict:
        """
        DNS 记录查询

        查询目标的 A、MX、NS、TXT 记录。

        Returns:
            包含各类 DNS 记录的字典
        """
        print(f"\n{Colors.BLUE}[*] DNS 记录查询: {self.target}{Colors.END}")
        records = {'A': [], 'MX': [], 'NS': [], 'TXT': [], 'CNAME': []}

        # A 记录
        try:
            ips = socket.getaddrinfo(self.target, None, socket.AF_INET, socket.SOCK_STREAM)
            seen = set()
            for info in ips:
                ip = info[4][0]
                if ip not in seen:
                    records['A'].append(ip)
                    seen.add(ip)
                    print(f"  {Colors.GREEN}[+] A 记录: {ip}{Colors.END}")
        except socket.gaierror:
            print(f"  {Colors.RED}[-] A 记录查询失败{Colors.END}")

        # CNAME 记录 (通过 socket 尝试)
        try:
            cname = socket.getfqdn(self.target)
            if cname and cname != self.target:
                records['CNAME'].append(cname)
                print(f"  {Colors.GREEN}[+] CNAME: {cname}{Colors.END}")
        except Exception:
            pass

        # 使用系统 nslookup/dig 查询 MX, NS, TXT
        for rtype in ['MX', 'NS', 'TXT']:
            try:
                import subprocess
                result = subprocess.run(
                    ['dig', '+short', self.target, rtype],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().split('\n'):
                        line = line.strip().strip('"')
                        if line:
                            records[rtype].append(line)
                            print(f"  {Colors.GREEN}[+] {rtype} 记录: {line}{Colors.END}")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # dig 不可用, 尝试 nslookup
                try:
                    import subprocess
                    result = subprocess.run(
                        ['nslookup', '-type=' + rtype, self.target],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.stdout:
                        for line in result.stdout.split('\n'):
                            if 'mail exchanger' in line.lower() or 'nameserver' in line.lower() or 'text' in line.lower():
                                parts = line.split('=') if '=' in line else line.split(':')
                                if len(parts) > 1:
                                    val = parts[-1].strip().strip('"')
                                    if val:
                                        records[rtype].append(val)
                                        print(f"  {Colors.GREEN}[+] {rtype} 记录: {val}{Colors.END}")
                except Exception:
                    pass
            except Exception as e:
                print(f"  {Colors.YELLOW}[!] {rtype} 查询异常: {e}{Colors.END}")

        if not any(records.values()):
            print(f"  {Colors.YELLOW}[!] 未找到 DNS 记录{Colors.END}")

        self.results['dns_records'] = records
        return records

    def http_info_gather(self) -> dict:
        """
        HTTP 信息收集

        获取 HTTP 响应头、服务器信息和技术栈识别。

        Returns:
            HTTP 信息字典
        """
        print(f"\n{Colors.BLUE}[*] HTTP 信息收集: {self.target}{Colors.END}")
        info = {
            'headers': {},
            'server': '未知',
            'technologies': [],
            'status_code': 0,
            'redirect_url': None,
        }

        if not HAS_REQUESTS:
            print(f"  {Colors.RED}[-] requests 库未安装, 跳过 HTTP 信息收集{Colors.END}")
            self.results['http_info'] = info
            return info

        for scheme in ['https', 'http']:
            url = f"{scheme}://{self.target}"
            try:
                resp = requests.get(url, timeout=10, allow_redirects=False, verify=False)
                info['status_code'] = resp.status_code
                info['headers'] = dict(resp.headers)
                info['server'] = resp.headers.get('Server', '未知')
                info['redirect_url'] = resp.headers.get('Location', None)

                print(f"  {Colors.GREEN}[+] URL: {url}{Colors.END}")
                print(f"  {Colors.GREEN}[+] 状态码: {resp.status_code}{Colors.END}")
                print(f"  {Colors.GREEN}[+] 服务器: {info['server']}{Colors.END}")

                # 技术栈识别
                powered_by = resp.headers.get('X-Powered-By', '')
                if powered_by:
                    info['technologies'].append(powered_by)
                    print(f"  {Colors.GREEN}[+] 技术栈: {powered_by}{Colors.END}")

                # 从 HTML 内容识别技术
                body = resp.text[:50000].lower()
                tech_signatures = {
                    'WordPress': ['wp-content', 'wp-includes'],
                    'Joomla': ['joomla', '/media/system/'],
                    'Drupal': ['drupal', 'sites/default/files'],
                    'Laravel': ['laravel', 'csrf-token'],
                    'Django': ['csrfmiddlewaretoken', '__admin__'],
                    'React': ['react', '_next/static'],
                    'Vue.js': ['vue.js', '__nuxt__'],
                    'jQuery': ['jquery'],
                    'Bootstrap': ['bootstrap'],
                    'Nginx': ['nginx'],
                    'Apache': ['apache'],
                    'PHP': ['.php'],
                    'ASP.NET': ['asp.net', '__viewstate'],
                }
                for tech, sigs in tech_signatures.items():
                    for sig in sigs:
                        if sig in body and tech not in info['technologies']:
                            info['technologies'].append(tech)
                            print(f"  {Colors.GREEN}[+] 检测到技术: {tech}{Colors.END}")
                            break

                # 安全头部检查
                security_headers = [
                    'X-Frame-Options', 'X-Content-Type-Options',
                    'X-XSS-Protection', 'Content-Security-Policy',
                    'Strict-Transport-Security'
                ]
                print(f"\n  {Colors.CYAN}[*] 安全头部检查:{Colors.END}")
                for hdr in security_headers:
                    if hdr in resp.headers:
                        print(f"  {Colors.GREEN}  [+] {hdr}: {resp.headers[hdr][:60]}{Colors.END}")
                    else:
                        print(f"  {Colors.YELLOW}  [!] {hdr}: 未设置{Colors.END}")

                break  # 成功则不尝试另一个 scheme
            except requests.exceptions.SSLError:
                print(f"  {Colors.YELLOW}[!] {scheme} SSL 错误, 尝试其他方式...{Colors.END}")
                continue
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                print(f"  {Colors.RED}[-] {scheme} 连接超时{Colors.END}")
                continue
            except Exception as e:
                print(f"  {Colors.RED}[-] {scheme} 请求失败: {e}{Colors.END}")
                continue

        self.results['http_info'] = info
        return info

    def subdomain_enum(self, wordlist_path: str = None, max_threads: int = 20) -> list:
        """
        子域名枚举

        使用常见子域名前缀进行 DNS 爆破。

        Args:
            wordlist_path: 子域名字典路径
            max_threads: 最大线程数

        Returns:
            发现的子域名列表
        """
        print(f"\n{Colors.BLUE}[*] 子域名枚举: {self.target}{Colors.END}")

        # 加载字典
        if wordlist_path is None:
            wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                         'wordlists', 'subdomains.txt')

        subdomains = []
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                prefixes = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"  {Colors.YELLOW}[!] 字典文件未找到, 使用内置前缀{Colors.END}")
            prefixes = [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
                'api', 'blog', 'shop', 'cdn', 'app', 'portal', 'vpn',
                'mx', 'ns1', 'ns2', 'dns', 'remote', 'gateway', 'proxy',
                'beta', 'demo', 'secure', 'sso', 'auth', 'crm', 'hr',
                'intranet', 'jira', 'confluence', 'gitlab', 'jenkins',
                'docs', 'support', 'help', 'status', 'monitor',
            ]

        print(f"  {Colors.CYAN}[*] 使用 {len(prefixes)} 个前缀进行枚举 (线程数: {max_threads}){Colors.END}")

        found = []
        lock = threading.Lock()

        def check_subdomain(prefix):
            """检查单个子域名是否存在"""
            subdomain = f"{prefix}.{self.target}"
            try:
                ip = socket.gethostbyname(subdomain)
                with lock:
                    found.append({'subdomain': subdomain, 'ip': ip})
                    print(f"  {Colors.GREEN}[+] 发现: {subdomain} -> {ip}{Colors.END}")
            except socket.gaierror:
                pass
            except Exception:
                pass

        # 多线程枚举
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(check_subdomain, p): p for p in prefixes}
            done = 0
            total = len(futures)
            for future in as_completed(futures):
                done += 1
                if done % 50 == 0 or done == total:
                    progress = done / total * 100
                    print(f"\r  {Colors.CYAN}[*] 进度: {progress:.0f}% ({done}/{total}){Colors.END}",
                          end='', flush=True)
                future.result()

        print(f"\n  {Colors.GREEN}[+] 共发现 {len(found)} 个子域名{Colors.END}")
        self.results['subdomains'] = found
        return found

    def sensitive_file_probe(self) -> dict:
        """
        敏感文件探测

        探测 robots.txt、sitemap.xml 等敏感文件。

        Returns:
            发现的敏感文件信息
        """
        print(f"\n{Colors.BLUE}[*] 敏感文件探测: {self.target}{Colors.END}")

        files_to_check = [
            ('robots.txt', 'Robots 文件'),
            ('sitemap.xml', '站点地图'),
            ('.well-known/security.txt', '安全联系信息'),
            ('.env', '环境变量文件'),
            ('wp-config.php.bak', 'WordPress 配置备份'),
            ('.git/HEAD', 'Git 仓库暴露'),
            ('.svn/entries', 'SVN 仓库暴露'),
            ('server-status', 'Apache 状态页'),
            ('server-info', 'Apache 信息页'),
            ('phpinfo.php', 'PHP 信息页'),
            ('.htaccess', 'Apache 配置文件'),
            ('web.config', 'IIS 配置文件'),
            ('crossdomain.xml', '跨域策略文件'),
        ]

        results = {}

        if not HAS_REQUESTS:
            print(f"  {Colors.RED}[-] requests 库未安装, 跳过敏感文件探测{Colors.END}")
            self.results['sensitive_files'] = results
            return results

        for filepath, description in files_to_check:
            for scheme in ['https', 'http']:
                url = f"{scheme}://{self.target}/{filepath}"
                try:
                    resp = requests.get(url, timeout=5, verify=False)
                    if resp.status_code == 200 and len(resp.text) > 0:
                        results[filepath] = {
                            'description': description,
                            'status': resp.status_code,
                            'size': len(resp.text),
                            'snippet': resp.text[:500],
                        }
                        print(f"  {Colors.GREEN}[+] {description}: {url} (200, {len(resp.text)} bytes){Colors.END}")

                        # 解析 robots.txt
                        if filepath == 'robots.txt':
                            self._parse_robots(resp.text)
                        # 解析 sitemap.xml
                        elif filepath == 'sitemap.xml':
                            self._parse_sitemap(resp.text)
                        break
                except Exception:
                    continue

        if not results:
            print(f"  {Colors.YELLOW}[!] 未发现敏感文件{Colors.END}")

        self.results['sensitive_files'] = results
        return results

    def _parse_robots(self, content: str):
        """解析 robots.txt 内容"""
        disallowed = re.findall(r'Disallow:\s*(.+)', content)
        if disallowed:
            print(f"  {Colors.CYAN}[*] robots.txt 中的禁止路径:{Colors.END}")
            for path in disallowed[:10]:
                print(f"      {path.strip()}")

    def _parse_sitemap(self, content: str):
        """解析 sitemap.xml 内容"""
        urls = re.findall(r'<loc>(.+?)</loc>', content)
        if urls:
            print(f"  {Colors.CYAN}[*] sitemap.xml 中的 URL (前10个):{Colors.END}")
            for url in urls[:10]:
                print(f"      {url}")

    def run(self) -> dict:
        """
        执行完整的信息收集流程

        Returns:
            所有收集结果的汇总字典
        """
        self._print_banner()
        print(f"\n{Colors.BOLD}[*] 目标: {self.target}{Colors.END}")
        print(f"{Colors.BOLD}[*] 开始信息收集...{Colors.END}")

        start_time = time.time()

        # 1. DNS 查询
        self.dns_lookup()

        # 2. HTTP 信息收集
        self.http_info_gather()

        # 3. 敏感文件探测
        self.sensitive_file_probe()

        # 4. 子域名枚举
        self.subdomain_enum()

        elapsed = time.time() - start_time
        print(f"\n{Colors.GREEN}[+] 信息收集完成 (耗时: {elapsed:.1f}s){Colors.END}")

        return self.results


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        module = ReconModule(sys.argv[1])
        module.run()
    else:
        print("用法: python -m modules.recon <目标域名>")
