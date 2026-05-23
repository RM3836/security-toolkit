#!/usr/bin/env python3
"""
Day4 实战：Web 漏洞扫描器 v1（信息收集 + 基础探测）
原理：
  - 对目标网站进行信息收集（HTTP头、技术栈识别）
  - 目录扫描（常见路径爆破）
  - 检测常见安全问题（敏感文件暴露、目录遍历、XSS反射等）

依赖：pip install requests
运行：python3 web_scanner_v1.py http://target.com
"""

import requests
import sys
import time
import json
import re
import argparse
from urllib.parse import urljoin, urlparse
from datetime import datetime

# 禁用 SSL 警告
requests.packages.urllib3.disable_warnings()

# 超时和并发配置
TIMEOUT = 10
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'


class WebScanner:
    """Web 漏洞扫描器"""

    def __init__(self, target):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.headers['User-Agent'] = USER_AGENT
        self.session.verify = False  # 忽略 SSL 证书
        self.findings = []  # 发现的问题

    def add_finding(self, severity, category, detail, url=''):
        """记录一个发现"""
        finding = {
            'severity': severity,  # HIGH / MEDIUM / LOW / INFO
            'category': category,
            'detail': detail,
            'url': url,
            'time': datetime.now().strftime('%H:%M:%S')
        }
        self.findings.append(finding)

        icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}
        print("  %s [%s] %s: %s" % (icon.get(severity, '?'), severity, category, detail))

    # ========== 信息收集 ==========

    def collect_info(self):
        """收集目标网站基本信息"""
        print("\n  [Phase 1] 信息收集")
        print("  %s" % "-" * 50)

        try:
            resp = self.session.get(self.target, timeout=TIMEOUT)
        except requests.exceptions.ConnectionError:
            print("  [!] 无法连接: %s" % self.target)
            return False
        except requests.exceptions.Timeout:
            print("  [!] 连接超时: %s" % self.target)
            return False

        # 状态码
        self.add_finding('INFO', '状态码', '%d' % resp.status_code, self.target)

        # HTTP 响应头分析
        headers = resp.headers
        server = headers.get('Server', '未公开')
        self.add_finding('INFO', 'Server', server)

        # 技术栈识别
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            self.add_finding('MEDIUM', '技术栈泄露', 'X-Powered-By: %s' % powered_by)

        # 安全头检测
        security_headers = {
            'X-Frame-Options': '点击劫持防护',
            'X-Content-Type-Options': 'MIME 类型嗅探防护',
            'X-XSS-Protection': 'XSS 防护',
            'Content-Security-Policy': 'CSP 内容安全策略',
            'Strict-Transport-Security': 'HSTS 强制 HTTPS',
            'Referrer-Policy': '引用策略',
        }

        for header, desc in security_headers.items():
            if header not in headers:
                self.add_finding('LOW', '缺少安全头', '%s (%s)' % (header, desc))

        # Cookie 检查
        for cookie in resp.cookies:
            flags = []
            if 'httponly' not in str(cookie).lower():
                flags.append('缺少 HttpOnly')
            if 'secure' not in str(cookie).lower():
                flags.append('缺少 Secure')
            if flags:
                self.add_finding('MEDIUM', 'Cookie 不安全',
                                 '%s: %s' % (cookie.name, ', '.join(flags)))

        # 检测 HTML 中的版本信息
        body = resp.text.lower()
        version_patterns = [
            (r'wordpress\s+[\d.]+', 'WordPress 版本'),
            (r'jquery[\s-]+([\d.]+)', 'jQuery 版本'),
            (r'bootstrap[\s/]+([\d.]+)', 'Bootstrap 版本'),
            (r'powered by\s+[\w\s]+', 'Powered By'),
        ]
        for pattern, name in version_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                self.add_finding('INFO', '版本信息', '%s: %s' % (name, match.group(0)))

        return True

    # ========== 目录扫描 ==========

    def scan_directories(self):
        """扫描常见敏感目录和文件"""
        print("\n  [Phase 2] 目录扫描")
        print("  %s" % "-" * 50)

        # 常见敏感路径（按重要性分组）
        paths = [
            # 配置/备份文件（HIGH）
            ('.env', 'HIGH', '环境配置文件（可能含数据库密码）'),
            ('.git/HEAD', 'HIGH', 'Git 仓库泄露'),
            ('.git/config', 'HIGH', 'Git 配置泄露'),
            ('wp-config.php', 'HIGH', 'WordPress 配置文件'),
            ('config.php', 'HIGH', 'PHP 配置文件'),
            ('database.yml', 'HIGH', '数据库配置'),
            ('backup.sql', 'HIGH', '数据库备份泄露'),
            ('backup.zip', 'HIGH', '备份文件泄露'),
            ('dump.sql', 'HIGH', '数据库导出泄露'),

            # 管理后台（MEDIUM）
            ('admin/', 'MEDIUM', '管理后台入口'),
            ('admin/login', 'MEDIUM', '管理登录页面'),
            ('wp-admin/', 'MEDIUM', 'WordPress 管理后台'),
            ('phpmyadmin/', 'MEDIUM', 'phpMyAdmin 入口'),
            ('manager/', 'MEDIUM', '管理入口'),

            # 常见目录（LOW）
            ('robots.txt', 'LOW', 'Robots 文件（信息收集）'),
            ('sitemap.xml', 'LOW', '站点地图'),
            ('.htaccess', 'LOW', 'Apache 配置文件'),
            ('server-status', 'LOW', 'Apache 状态页'),
            ('server-info', 'LOW', 'Apache 信息页'),
            ('info.php', 'LOW', 'PHP 信息泄露'),
            ('test.php', 'LOW', '测试文件'),
            ('readme.html', 'LOW', 'README 文件'),
            ('CHANGELOG.md', 'LOW', '变更日志'),
            ('LICENSE', 'INFO', '许可证文件'),

            # API 端点（MEDIUM）
            ('api/', 'MEDIUM', 'API 入口'),
            ('api/v1/', 'MEDIUM', 'API v1 入口'),
            ('swagger.json', 'MEDIUM', 'Swagger API 文档'),
            ('graphql', 'MEDIUM', 'GraphQL 端点'),
        ]

        found = 0
        for path, severity, desc in paths:
            url = urljoin(self.target + '/', path)
            try:
                resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=False)
                if resp.status_code == 200:
                    # 二次确认：检查是否是自定义 404 页面
                    if len(resp.text) > 50 and 'not found' not in resp.text.lower()[:500]:
                        self.add_finding(severity, '目录发现', '%s (%s)' % (path, desc), url)
                        found += 1

                        # 如果是敏感文件，尝试读取部分内容
                        if severity == 'HIGH' and path in ['.env', '.git/HEAD', 'robots.txt']:
                            preview = resp.text[:200].replace('\n', '\n      ')
                            self.add_finding('INFO', '文件预览', '%s:\n      %s' % (path, preview))

                elif resp.status_code == 403:
                    self.add_finding('LOW', '目录存在(403)', '%s (被禁止访问)' % path, url)

            except requests.exceptions.RequestException:
                pass

            # 控制扫描速率，避免被封
            time.sleep(0.1)

        if found == 0:
            print("  [✓] 未发现敏感目录")

    # ========== 漏洞检测 ==========

    def check_xss_reflection(self):
        """检测反射型 XSS"""
        print("\n  [Phase 3] XSS 反射检测")
        print("  %s" % "-" * 50)

        test_payloads = [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "';alert(1)//",
        ]

        # 测试 URL 参数
        test_url = self.target + '?q=test'
        for payload in test_payloads:
            try:
                resp = self.session.get(
                    self.target + '?q=' + payload,
                    timeout=TIMEOUT
                )
                if payload in resp.text:
                    self.add_finding('HIGH', 'XSS 反射',
                                     '参数 q 中反射了 payload', resp.url)
                    break
            except:
                pass

    def check_sensitive_info(self):
        """检测敏感信息泄露"""
        print("\n  [Phase 4] 敏感信息检测")
        print("  %s" % "-" * 50)

        try:
            resp = self.session.get(self.target, timeout=TIMEOUT)
            body = resp.text
        except:
            return

        # 检测邮箱泄露
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
        if emails:
            unique_emails = list(set(emails))[:5]
            self.add_finding('MEDIUM', '邮箱泄露', str(unique_emails))

        # 检测内网 IP 泄露
        ips = re.findall(r'(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}', body)
        if ips:
            self.add_finding('MEDIUM', '内网IP泄露', str(list(set(ips))))

        # 检测注释中的敏感信息
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        for comment in comments:
            sensitive_words = ['password', 'todo', 'fixme', 'hack', 'secret', 'key', 'token']
            for word in sensitive_words:
                if word in comment.lower():
                    self.add_finding('LOW', '注释敏感信息',
                                     'HTML 注释含 "%s": %s' % (word, comment[:100]))

    def check_open_redirect(self):
        """检测开放重定向"""
        print("\n  [Phase 5] 开放重定向检测")
        print("  %s" % "-" * 50)

        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'continue', 'dest']
        for param in redirect_params:
            test_url = '%s?%s=https://evil.com' % (self.target, param)
            try:
                resp = self.session.get(test_url, timeout=TIMEOUT, allow_redirects=False)
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get('Location', '')
                    if 'evil.com' in location:
                        self.add_finding('HIGH', '开放重定向',
                                         '参数 %s 可重定向到外部' % param, test_url)
            except:
                pass

    # ========== 生成报告 ==========

    def generate_report(self):
        """生成扫描报告"""
        print("\n" + "=" * 60)
        print("  Web 漏洞扫描报告")
        print("  目标: %s" % self.target)
        print("  时间: %s" % datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print("=" * 60)

        # 统计
        severity_count = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            severity_count[f['severity']] = severity_count.get(f['severity'], 0) + 1

        print("\n  风险统计:")
        print("  🔴 HIGH:   %d" % severity_count.get('HIGH', 0))
        print("  🟡 MEDIUM: %d" % severity_count.get('MEDIUM', 0))
        print("  🟢 LOW:    %d" % severity_count.get('LOW', 0))
        print("  ℹ️  INFO:   %d" % severity_count.get('INFO', 0))
        print("  总计:      %d" % len(self.findings))

        # 按严重程度输出
        for sev in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
            items = [f for f in self.findings if f['severity'] == sev]
            if items:
                print("\n  --- %s ---" % sev)
                for f in items:
                    print("  [%s] %s: %s" % (f['time'], f['category'], f['detail']))
                    if f['url']:
                        print("    URL: %s" % f['url'])

        print("\n" + "=" * 60)

        # 保存 JSON
        report_file = "web_scan_%s.json" % time.strftime('%Y%m%d_%H%M%S')
        output = {
            'target': self.target,
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': severity_count,
            'total': len(self.findings),
            'findings': self.findings
        }
        with open(report_file, 'w') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print("  报告已保存: %s" % report_file)

    def run(self):
        """执行完整扫描"""
        print("=" * 60)
        print("  Web 漏洞扫描器 v1 - Day4 实战")
        print("  作者: YURM | 日期: 2026-05-23")
        print("=" * 60)

        start = time.time()

        if not self.collect_info():
            return

        self.scan_directories()
        self.check_xss_reflection()
        self.check_sensitive_info()
        self.check_open_redirect()

        elapsed = time.time() - start
        print("\n  扫描耗时: %.1f 秒" % elapsed)

        self.generate_report()


def main():
    parser = argparse.ArgumentParser(description='Day4: Web 漏洞扫描器')
    parser.add_argument('target', help='目标 URL (如 http://example.com)')
    parser.add_argument('--no-dir', action='store_true', help='跳过目录扫描')
    args = parser.parse_args()

    # 确保有协议前缀
    target = args.target
    if not target.startswith('http'):
        target = 'http://' + target

    scanner = WebScanner(target)
    scanner.run()


if __name__ == "__main__":
    main()
