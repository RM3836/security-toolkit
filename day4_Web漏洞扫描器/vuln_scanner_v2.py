#!/usr/bin/env python3
"""
Day4 实战：Web 漏洞扫描器 v2（SQL注入 + XSS 深度检测）
原理：
  - SQL 注入检测：基于错误回显、布尔盲注、时间盲注
  - XSS 检测：反射型 + DOM 型
  - 命令注入检测
  - 路径遍历检测

与 v1 的关系：v1 是信息收集+目录扫描，v2 是漏洞深度检测
依赖：pip install requests
运行：python3 vuln_scanner_v2.py http://target.com
"""

import requests
import sys
import time
import json
import re
import argparse
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime

requests.packages.urllib3.disable_warnings()

TIMEOUT = 10
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'


class VulnScanner:
    """深度漏洞扫描器"""

    def __init__(self, target):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.headers['User-Agent'] = USER_AGENT
        self.session.verify = False
        self.findings = []

    def add_finding(self, severity, category, detail, url='', evidence=''):
        finding = {
            'severity': severity,
            'category': category,
            'detail': detail,
            'url': url,
            'evidence': evidence[:200] if evidence else '',
            'time': datetime.now().strftime('%H:%M:%S')
        }
        self.findings.append(finding)
        icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}
        print("  %s [%s] %s: %s" % (icon.get(severity, '?'), severity, category, detail))

    # ========== SQL 注入检测 ==========

    def test_sqli(self):
        """SQL 注入检测"""
        print("\n  [Phase 1] SQL 注入检测")
        print("  %s" % "-" * 50)

        # Step 1: 获取正常响应基线
        try:
            normal = self.session.get(self.target, timeout=TIMEOUT)
            normal_len = len(normal.text)
            normal_status = normal.status_code
        except:
            print("  [!] 无法访问目标")
            return

        # Step 2: SQL 错误关键词
        sqli_errors = [
            'sql syntax', 'mysql_fetch', 'sqlite3', 'ORA-', 'postgresql',
            'Microsoft OLE DB', 'unclosed quotation', 'ODBC SQL Server',
            'JET Database Engine', 'Warning: mysql', 'MySqlException',
            'valid MySQL result', 'pg_query', 'SQLite/JDBCDriver',
            'SQLSTATE', 'Syntax error', 'unterminated quoted string'
        ]

        # Step 3: 测试 Payloads
        sqli_payloads = [
            # 经典注入
            ("'", "单引号注入"),
            ('" OR 1=1 --', "OR 注入"),
            ("' OR '1'='1", "字符串 OR 注入"),
            ("1; SELECT * FROM users--", "堆叠查询"),
            ("' UNION SELECT NULL--", "UNION 注入探测"),
            # 数字型
            ("1 OR 1=1", "数字型 OR 注入"),
            ("1 AND 1=2", "数字型 AND 假"),
            # 特殊字符
            ("') OR ('1'='1", "括号闭合注入"),
            ("admin'--", "注释截断"),
        ]

        # 测试 URL 参数
        test_params = ['id', 'page', 'cat', 'search', 'q', 'user', 'item']

        for param in test_params:
            for payload, desc in sqli_payloads:
                test_url = '%s?%s=%s' % (self.target, param, payload)
                try:
                    resp = self.session.get(test_url, timeout=TIMEOUT)

                    # 检测 1：错误回显
                    for error in sqli_errors:
                        if error.lower() in resp.text.lower():
                            self.add_finding('HIGH', 'SQL注入(错误回显)',
                                             '参数 %s, payload: %s (%s)' % (param, payload, desc),
                                             test_url, error)
                            return  # 找到一个就够了

                    # 检测 2：响应长度异常（布尔盲注特征）
                    len_diff = abs(len(resp.text) - normal_len)
                    if len_diff > normal_len * 0.5 and normal_len > 100:
                        self.add_finding('MEDIUM', 'SQL注入(响应异常)',
                                         '参数 %s, 长度变化 %d -> %d' % (param, normal_len, len(resp.text)),
                                         test_url)

                except:
                    pass
                time.sleep(0.05)

        # 时间盲注检测
        time_payloads = [
            ("' OR SLEEP(3)--", 3),
            ("'; WAITFOR DELAY '0:0:3'--", 3),
            ("' OR pg_sleep(3)--", 3),
        ]

        for param in test_params[:2]:  # 只测前两个参数
            for payload, delay in time_payloads:
                test_url = '%s?%s=%s' % (self.target, param, payload)
                try:
                    start = time.time()
                    resp = self.session.get(test_url, timeout=delay + 5)
                    elapsed = time.time() - start

                    if elapsed >= delay * 0.8:
                        self.add_finding('HIGH', 'SQL注入(时间盲注)',
                                         '参数 %s, 延迟 %.1fs (预期 %ds)' % (param, elapsed, delay),
                                         test_url)
                        return
                except:
                    pass

        print("  [✓] 未检测到 SQL 注入")

    # ========== XSS 深度检测 ==========

    def test_xss(self):
        """XSS 深度检测"""
        print("\n  [Phase 2] XSS 深度检测")
        print("  %s" % "-" * 50)

        xss_payloads = [
            ('<script>alert(1)</script>', '基础 script 标签'),
            ('"><img src=x onerror=alert(1)>', 'img onerror'),
            ("'><svg/onload=alert(1)>", 'svg onload'),
            ('javascript:alert(1)', 'javascript 协议'),
            ('<details open ontoggle=alert(1)>', 'details ontoggle'),
            ('{{7*7}}', '模板注入检测'),
            ('${7*7}', '表达式注入'),
        ]

        test_params = ['q', 'search', 'name', 'input', 'text', 'msg', 'comment']

        for param in test_params:
            for payload, desc in xss_payloads:
                test_url = '%s?%s=%s' % (self.target, param, requests.utils.quote(payload))
                try:
                    resp = self.session.get(test_url, timeout=TIMEOUT)

                    # 检查 payload 是否原样反射
                    if payload in resp.text:
                        self.add_finding('HIGH', 'XSS 反射',
                                         '参数 %s: %s' % (param, desc),
                                         test_url, payload)
                        return

                    # 检查模板注入
                    if payload == '{{7*7}}' and '49' in resp.text:
                        self.add_finding('HIGH', '模板注入(SSTI)',
                                         '参数 %s 可能存在模板注入' % param,
                                         test_url)
                    if payload == '${7*7}' and '49' in resp.text:
                        self.add_finding('HIGH', '表达式注入(SPEL/EL)',
                                         '参数 %s 可能存在表达式注入' % param,
                                         test_url)

                except:
                    pass
                time.sleep(0.05)

        print("  [✓] 未检测到 XSS")

    # ========== 路径遍历 ==========

    def test_path_traversal(self):
        """路径遍历检测"""
        print("\n  [Phase 3] 路径遍历检测")
        print("  %s" % "-" * 50)

        # 不同平台的敏感文件
        traversal_payloads = [
            ('../../../etc/passwd', 'root:', 'Linux /etc/passwd'),
            ('..\\..\\..\\windows\\win.ini', '[fonts]', 'Windows win.ini'),
            ('../../../etc/hosts', 'localhost', 'Linux /etc/hosts'),
            ('/etc/passwd', 'root:', '绝对路径 /etc/passwd'),
        ]

        test_params = ['file', 'path', 'page', 'include', 'doc', 'lang']

        for param in test_params:
            for payload, marker, desc in traversal_payloads:
                test_url = '%s?%s=%s' % (self.target, param, payload)
                try:
                    resp = self.session.get(test_url, timeout=TIMEOUT)
                    if marker in resp.text and resp.status_code == 200:
                        self.add_finding('HIGH', '路径遍历',
                                         '参数 %s: %s' % (param, desc),
                                         test_url, marker)
                        return
                except:
                    pass

        print("  [✓] 未检测到路径遍历")

    # ========== 命令注入 ==========

    def test_command_injection(self):
        """命令注入检测"""
        print("\n  [Phase 4] 命令注入检测")
        print("  %s" % "-" * 50)

        # 基于时间的检测
        cmd_payloads = [
            ('; sleep 3', 3, '分号注入'),
            ('| sleep 3', 3, '管道注入'),
            ('`sleep 3`', 3, '反引号注入'),
            ('$(sleep 3)', 3, '命令替换注入'),
            ('&& ping -c 3 127.0.0.1', 3, 'AND 注入'),
        ]

        test_params = ['cmd', 'host', 'ip', 'target', 'ping', 'url']

        for param in test_params[:2]:
            for payload, delay, desc in cmd_payloads:
                test_url = '%s?%s=127.0.0.1%s' % (self.target, param, payload)
                try:
                    start = time.time()
                    resp = self.session.get(test_url, timeout=delay + 5)
                    elapsed = time.time() - start

                    if elapsed >= delay * 0.8:
                        self.add_finding('HIGH', '命令注入',
                                         '参数 %s: %s, 延迟 %.1fs' % (param, desc, elapsed),
                                         test_url)
                        return
                except:
                    pass

        print("  [✓] 未检测到命令注入")

    # ========== HTTP 方法测试 ==========

    def test_http_methods(self):
        """测试危险 HTTP 方法"""
        print("\n  [Phase 5] HTTP 方法检测")
        print("  %s" % "-" * 50)

        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS']

        for method in dangerous_methods:
            try:
                resp = self.session.request(method, self.target, timeout=TIMEOUT)
                if resp.status_code not in [403, 405, 501]:
                    self.add_finding('MEDIUM', '危险HTTP方法',
                                     '%s 返回 %d' % (method, resp.status_code),
                                     self.target)

                    # TRACE 方法特别危险（XST 攻击）
                    if method == 'TRACE' and resp.status_code == 200:
                        self.add_finding('HIGH', 'TRACE 方法启用',
                                         '可进行跨站追踪(XST)攻击', self.target)
            except:
                pass

    # ========== 报告 ==========

    def generate_report(self):
        print("\n" + "=" * 60)
        print("  深度漏洞扫描报告")
        print("  目标: %s" % self.target)
        print("  时间: %s" % datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print("=" * 60)

        severity_count = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            severity_count[f['severity']] += 1

        print("\n  风险统计:")
        print("  🔴 HIGH:   %d" % severity_count.get('HIGH', 0))
        print("  🟡 MEDIUM: %d" % severity_count.get('MEDIUM', 0))
        print("  🟢 LOW:    %d" % severity_count.get('LOW', 0))
        print("  ℹ️  INFO:   %d" % severity_count.get('INFO', 0))

        for sev in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
            items = [f for f in self.findings if f['severity'] == sev]
            if items:
                print("\n  --- %s ---" % sev)
                for f in items:
                    print("  [%s] %s: %s" % (f['time'], f['category'], f['detail']))
                    if f['url']:
                        print("    URL: %s" % f['url'])
                    if f['evidence']:
                        print("    证据: %s" % f['evidence'][:100])

        print("\n" + "=" * 60)

        report_file = "vuln_scan_%s.json" % time.strftime('%Y%m%d_%H%M%S')
        with open(report_file, 'w') as f:
            json.dump({
                'target': self.target,
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'summary': severity_count,
                'findings': self.findings
            }, f, indent=2, ensure_ascii=False)
        print("  报告已保存: %s" % report_file)

    def run(self):
        print("=" * 60)
        print("  Web 漏洞扫描器 v2 - Day4 实战（深度检测版）")
        print("  作者: YURM | 日期: 2026-05-23")
        print("=" * 60)
        print("\n  ⚠ 仅用于授权测试！未经授权的扫描是违法行为。\n")

        start = time.time()

        self.test_sqli()
        self.test_xss()
        self.test_path_traversal()
        self.test_command_injection()
        self.test_http_methods()

        print("\n  扫描耗时: %.1f 秒" % (time.time() - start))
        self.generate_report()


def main():
    parser = argparse.ArgumentParser(description='Day4: 深度漏洞扫描器')
    parser.add_argument('target', help='目标 URL')
    args = parser.parse_args()

    target = args.target
    if not target.startswith('http'):
        target = 'http://' + target

    VulnScanner(target).run()


if __name__ == "__main__":
    main()
