#!/usr/bin/env python3
"""
Day5 实战：日志分析系统 v1（日志解析 + 统计分析）
原理：
  - 解析 Linux auth.log / access.log 等常见日志格式
  - 统计登录失败、IP 访问频率、异常行为
  - 生成可视化文本报告

依赖：标准库即可（re, collections, datetime）
运行：python3 log_analyzer_v1.py /var/log/auth.log
      python3 log_analyzer_v1.py access.log --type nginx
"""

import re
import sys
import json
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta


class LogAnalyzer:
    """通用日志分析器"""

    # 日志格式正则
    PATTERNS = {
        'auth': {
            # Jan  1 12:00:00 server sshd[1234]: Failed password for root from 1.2.3.4
            'failed_login': re.compile(
                r'(\w+ +\d+ [\d:]+) \S+ sshd\[\d+\]: Failed password for (\S+) from (\S+)'
            ),
            'success_login': re.compile(
                r'(\w+ +\d+ [\d:]+) \S+ sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+)'
            ),
            'invalid_user': re.compile(
                r'(\w+ +\d+ [\d:]+) \S+ sshd\[\d+\]: Invalid user (\S+) from (\S+)'
            ),
            'sudo': re.compile(
                r'(\w+ +\d+ [\d:]+) \S+ sudo:\s+(\S+) : .* COMMAND=(.*)'
            ),
        },
        'nginx': {
            # 1.2.3.4 - - [01/Jan/2026:12:00:00 +0800] "GET /path HTTP/1.1" 200 1234
            'access': re.compile(
                r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+|-)'
            ),
        },
        'apache': {
            'access': re.compile(
                r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+|-)'
            ),
        },
        'syslog': {
            'general': re.compile(
                r'(\w+ +\d+ [\d:]+) (\S+) (\S+?)(\[\d+\])?: (.+)'
            ),
        }
    }

    def __init__(self, log_type='auth'):
        self.log_type = log_type
        self.stats = {
            'total_lines': 0,
            'parsed_lines': 0,
            'failed_logins': [],        # (time, user, ip)
            'success_logins': [],       # (time, method, user, ip)
            'invalid_users': [],        # (time, user, ip)
            'sudo_commands': [],        # (time, user, command)
            'access_logs': [],          # (ip, time, method, path, status, size)
            'ip_counter': Counter(),
            'user_counter': Counter(),
            'status_counter': Counter(),
            'path_counter': Counter(),
            'hourly_dist': defaultdict(int),
        }

    def parse_line(self, line):
        """解析单行日志"""
        self.stats['total_lines'] += 1
        patterns = self.PATTERNS.get(self.log_type, {})

        if self.log_type == 'auth':
            # 失败登录
            m = patterns['failed_login'].search(line)
            if m:
                self.stats['failed_logins'].append((m.group(1), m.group(2), m.group(3)))
                self.stats['ip_counter'][m.group(3)] += 1
                self.stats['user_counter'][m.group(2)] += 1
                self.stats['parsed_lines'] += 1
                return

            # 成功登录
            m = patterns['success_login'].search(line)
            if m:
                self.stats['success_logins'].append(
                    (m.group(1), m.group(2), m.group(3), m.group(4)))
                self.stats['ip_counter'][m.group(4)] += 1
                self.stats['parsed_lines'] += 1
                return

            # 无效用户
            m = patterns['invalid_user'].search(line)
            if m:
                self.stats['invalid_users'].append((m.group(1), m.group(2), m.group(3)))
                self.stats['ip_counter'][m.group(3)] += 1
                self.stats['parsed_lines'] += 1
                return

            # sudo 命令
            m = patterns['sudo'].search(line)
            if m:
                self.stats['sudo_commands'].append((m.group(1), m.group(2), m.group(3)))
                self.stats['parsed_lines'] += 1
                return

        elif self.log_type in ('nginx', 'apache'):
            m = patterns['access'].search(line)
            if m:
                ip, time_str, method, path, status, size = m.groups()
                self.stats['access_logs'].append((ip, time_str, method, path, status, size))
                self.stats['ip_counter'][ip] += 1
                self.stats['status_counter'][status] += 1
                self.stats['path_counter'][path] += 1

                # 小时分布
                try:
                    hour = time_str.split(':')[1]
                    self.stats['hourly_dist'][hour] += 1
                except:
                    pass

                self.stats['parsed_lines'] += 1

    def analyze_file(self, filepath):
        """分析日志文件"""
        print("  读取文件: %s" % filepath)
        try:
            with open(filepath, 'r', errors='ignore') as f:
                for line in f:
                    self.parse_line(line.strip())
        except FileNotFoundError:
            print("  [!] 文件不存在: %s" % filepath)
            return False
        print("  解析: %d / %d 行" % (self.stats['parsed_lines'], self.stats['total_lines']))
        return True

    def detect_brute_force(self, threshold=5):
        """检测暴力破解"""
        alerts = []
        ip_failures = Counter()
        for _, user, ip in self.stats['failed_logins']:
            ip_failures[ip] += 1

        for ip, count in ip_failures.most_common(10):
            if count >= threshold:
                users_tried = set()
                for _, user, src_ip in self.stats['failed_logins']:
                    if src_ip == ip:
                        users_tried.add(user)
                alerts.append({
                    'type': '暴力破解',
                    'ip': ip,
                    'failures': count,
                    'users_tried': list(users_tried)[:10],
                    'severity': 'HIGH' if count > 20 else 'MEDIUM'
                })
        return alerts

    def detect_suspicious_access(self, threshold=100):
        """检测可疑 Web 访问"""
        alerts = []

        # 高频 IP
        for ip, count in self.stats['ip_counter'].most_common(5):
            if count > threshold:
                alerts.append({
                    'type': '高频访问',
                    'ip': ip,
                    'count': count,
                    'severity': 'MEDIUM'
                })

        # 4xx/5xx 错误率
        total = sum(self.stats['status_counter'].values())
        errors_4xx = sum(v for k, v in self.stats['status_counter'].items() if k.startswith('4'))
        errors_5xx = sum(v for k, v in self.stats['status_counter'].items() if k.startswith('5'))

        if total > 0:
            if errors_4xx / total > 0.3:
                alerts.append({
                    'type': '高 4xx 错误率',
                    'rate': '%.1f%%' % (errors_4xx / total * 100),
                    'severity': 'MEDIUM'
                })

        # 扫描特征路径
        scan_paths = ['/admin', '/wp-admin', '/.env', '/phpmyadmin', '/shell',
                      '/cmd', '/eval', '/../../../', '/etc/passwd']
        for path, count in self.stats['path_counter'].items():
            for scan_path in scan_paths:
                if scan_path in path:
                    alerts.append({
                        'type': '可疑路径访问',
                        'path': path,
                        'count': count,
                        'severity': 'HIGH'
                    })

        return alerts

    def print_report(self):
        """打印分析报告"""
        print("\n" + "=" * 60)
        print("  日志分析报告")
        print("  日志类型: %s" % self.log_type)
        print("  时间: %s" % datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print("=" * 60)

        total = self.stats['total_lines']
        parsed = self.stats['parsed_lines']
        print("\n  [1] 解析统计")
        print("  %s" % "-" * 40)
        print("  总行数:   %d" % total)
        print("  已解析:   %d (%.1f%%)" % (parsed, parsed / max(total, 1) * 100))

        if self.log_type == 'auth':
            # 登录失败统计
            print("\n  [2] 登录失败统计")
            print("  %s" % "-" * 40)
            print("  失败次数: %d" % len(self.stats['failed_logins']))
            print("  成功次数: %d" % len(self.stats['success_logins']))
            print("  无效用户: %d" % len(self.stats['invalid_users']))

            # TOP 失败 IP
            print("\n  [3] TOP 10 登录失败 IP")
            print("  %s" % "-" * 40)
            ip_failures = Counter(ip for _, _, ip in self.stats['failed_logins'])
            for ip, cnt in ip_failures.most_common(10):
                print("  %-18s %5d 次" % (ip, cnt))

            # TOP 失败用户名
            print("\n  [4] TOP 10 尝试的用户名")
            print("  %s" % "-" * 40)
            user_failures = Counter(user for _, user, _ in self.stats['failed_logins'])
            for user, cnt in user_failures.most_common(10):
                print("  %-18s %5d 次" % (user, cnt))

            # 成功登录记录
            if self.stats['success_logins']:
                print("\n  [5] 成功登录记录")
                print("  %s" % "-" * 40)
                for time_str, method, user, ip in self.stats['success_logins'][-10:]:
                    print("  [%s] %s@%s (%s)" % (time_str, user, ip, method))

            # sudo 命令
            if self.stats['sudo_commands']:
                print("\n  [6] sudo 命令记录")
                print("  %s" % "-" * 40)
                for time_str, user, cmd in self.stats['sudo_commands'][-10:]:
                    print("  [%s] %s: %s" % (time_str, user, cmd[:60]))

            # 暴力破解检测
            alerts = self.detect_brute_force()
            if alerts:
                print("\n  [!] 暴力破解告警")
                print("  %s" % "-" * 40)
                for a in alerts:
                    print("  %s IP: %s  失败 %d 次  尝试用户: %s" % (
                        '🔴' if a['severity'] == 'HIGH' else '🟡',
                        a['ip'], a['failures'],
                        ', '.join(a['users_tried'][:5])
                    ))

        elif self.log_type in ('nginx', 'apache'):
            # 状态码分布
            print("\n  [2] HTTP 状态码分布")
            print("  %s" % "-" * 40)
            for status, cnt in self.stats['status_counter'].most_common():
                pct = cnt / max(sum(self.stats['status_counter'].values()), 1) * 100
                print("  %-6s %6d (%5.1f%%)" % (status, cnt, pct))

            # TOP IP
            print("\n  [3] TOP 10 访问 IP")
            print("  %s" % "-" * 40)
            for ip, cnt in self.stats['ip_counter'].most_common(10):
                print("  %-18s %6d 次" % (ip, cnt))

            # TOP 路径
            print("\n  [4] TOP 10 访问路径")
            print("  %s" % "-" * 40)
            for path, cnt in self.stats['path_counter'].most_common(10):
                print("  %-40s %5d" % (path[:40], cnt))

            # 小时分布
            if self.stats['hourly_dist']:
                print("\n  [5] 小时分布")
                print("  %s" % "-" * 40)
                for hour in sorted(self.stats['hourly_dist'].keys()):
                    cnt = self.stats['hourly_dist'][hour]
                    bar = '#' * (cnt // max(1, max(self.stats['hourly_dist'].values()) // 40))
                    print("  %s:00  %5d %s" % (hour, cnt, bar))

            # 可疑访问检测
            alerts = self.detect_suspicious_access()
            if alerts:
                print("\n  [!] 可疑访问告警")
                print("  %s" % "-" * 40)
                for a in alerts:
                    icon = '🔴' if a['severity'] == 'HIGH' else '🟡'
                    if 'ip' in a:
                        print("  %s %s: %s (%d 次)" % (icon, a['type'], a['ip'], a['count']))
                    elif 'path' in a:
                        print("  %s %s: %s (%d 次)" % (icon, a['type'], a['path'], a['count']))
                    else:
                        print("  %s %s: %s" % (icon, a['type'], a.get('rate', '')))

        print("\n" + "=" * 60)

    def save_report(self, filename):
        """保存 JSON 报告"""
        output = {
            'log_type': self.log_type,
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_lines': self.stats['total_lines'],
            'parsed_lines': self.stats['parsed_lines'],
            'top_ips': dict(self.stats['ip_counter'].most_common(20)),
        }
        if self.log_type == 'auth':
            output['failed_login_count'] = len(self.stats['failed_logins'])
            output['success_login_count'] = len(self.stats['success_logins'])
            output['alerts'] = self.detect_brute_force()
        elif self.log_type in ('nginx', 'apache'):
            output['status_codes'] = dict(self.stats['status_counter'].most_common())
            output['top_paths'] = dict(self.stats['path_counter'].most_common(20))
            output['alerts'] = self.detect_suspicious_access()

        with open(filename, 'w') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print("  报告已保存: %s" % filename)


def main():
    parser = argparse.ArgumentParser(description='Day5: 日志分析系统')
    parser.add_argument('logfile', help='日志文件路径')
    parser.add_argument('--type', choices=['auth', 'nginx', 'apache', 'syslog'],
                        default='auth', help='日志类型 (默认 auth)')
    args = parser.parse_args()

    print("=" * 60)
    print("  日志分析系统 v1 - Day5 实战")
    print("  作者: YURM | 日期: 2026-05-23")
    print("=" * 60)

    analyzer = LogAnalyzer(args.type)
    if not analyzer.analyze_file(args.logfile):
        sys.exit(1)

    analyzer.print_report()
    report_file = "log_report_%s.json" % time.strftime('%Y%m%d_%H%M%S')
    analyzer.save_report(report_file)


if __name__ == "__main__":
    main()
