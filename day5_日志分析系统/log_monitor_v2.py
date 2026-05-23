#!/usr/bin/env python3
"""
Day5 实战：日志分析系统 v2（实时监控 + 告警）
原理：
  - 实时 tail -f 监控日志文件变化
  - 检测到暴力破解/异常行为时实时告警
  - 支持邮件/webhook 通知（可选）
  - 维护滑动窗口统计

依赖：标准库 + watchdog (pip install watchdog)
运行：sudo python3 log_monitor_v2.py /var/log/auth.log
"""

import sys
import time
import json
import re
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False


class BruteForceDetector:
    """暴力破解检测器（滑动窗口）"""

    def __init__(self, window_sec=300, threshold=5):
        self.window = window_sec    # 滑动窗口（秒）
        self.threshold = threshold  # 告警阈值
        self.ip_events = defaultdict(list)  # ip -> [timestamp, ...]
        self.alerted_ips = set()  # 已告警的 IP（避免重复）

    def record_failure(self, ip, user, timestamp=None):
        """记录一次失败登录"""
        now = timestamp or time.time()
        self.ip_events[ip].append(now)

        # 清理过期记录
        cutoff = now - self.window
        self.ip_events[ip] = [t for t in self.ip_events[ip] if t > cutoff]

        # 检查阈值
        count = len(self.ip_events[ip])
        if count >= self.threshold and ip not in self.alerted_ips:
            self.alerted_ips.add(ip)
            return {
                'type': 'BRUTE_FORCE',
                'ip': ip,
                'user': user,
                'count': count,
                'window_sec': self.window,
                'severity': 'CRITICAL' if count > 20 else 'HIGH'
            }
        return None

    def record_success(self, ip):
        """记录成功登录（清除该 IP 的失败计数）"""
        if ip in self.ip_events:
            del self.ip_events[ip]
        self.alerted_ips.discard(ip)


class LogMonitor:
    """实时日志监控器"""

    def __init__(self, logfile, log_type='auth'):
        self.logfile = logfile
        self.log_type = log_type
        self.detector = BruteForceDetector(window_sec=300, threshold=5)
        self.alerts = []
        self.stats = {'lines': 0, 'alerts': 0, 'start_time': time.time()}

        # 编译正则
        self.re_failed = re.compile(
            r'Failed password for (\S+) from (\S+)')
        self.re_invalid = re.compile(
            r'Invalid user (\S+) from (\S+)')
        self.re_accepted = re.compile(
            r'Accepted (\S+) for (\S+) from (\S+)')

    def process_line(self, line):
        """处理单行日志"""
        self.stats['lines'] += 1

        # 失败登录
        m = self.re_failed.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            alert = self.detector.record_failure(ip, user)
            if alert:
                self.trigger_alert(alert)
            return

        # 无效用户
        m = self.re_invalid.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            alert = self.detector.record_failure(ip, user)
            if alert:
                self.trigger_alert(alert)
            return

        # 成功登录
        m = self.re_accepted.search(line)
        if m:
            method, user, ip = m.group(1), m.group(2), m.group(3)
            self.detector.record_success(ip)
            self.print_event('LOGIN_OK', '%s@%s (%s)' % (user, ip, method))

    def trigger_alert(self, alert):
        """触发告警"""
        self.alerts.append(alert)
        self.stats['alerts'] += 1

        severity_colors = {
            'CRITICAL': '\033[91m',  # 红色
            'HIGH': '\033[93m',      # 黄色
            'MEDIUM': '\033[94m',    # 蓝色
        }
        reset = '\033[0m'
        color = severity_colors.get(alert['severity'], '')

        print("\n%s  %s🚨 [%s] %s%s" % (
            color,
            '=' * 40,
            alert['severity'],
            alert['type'],
            reset
        ))
        print("  IP:      %s" % alert['ip'])
        print("  用户:    %s" % alert['user'])
        print("  失败次数: %d (在 %d 秒内)" % (alert['count'], alert['window_sec']))
        print("  时间:    %s" % datetime.now().strftime('%H:%M:%S'))
        print("%s  %s%s" % (color, '=' * 40, reset))

    def print_event(self, event_type, detail):
        """打印普通事件"""
        ts = datetime.now().strftime('%H:%M:%S')
        if event_type == 'LOGIN_OK':
            print("  [%s] ✅ %s" % (ts, detail))

    def print_status(self):
        """打印状态摘要"""
        elapsed = time.time() - self.stats['start_time']
        print("\n  --- 状态 ---")
        print("  监控: %.0f 秒 | 行: %d | 告警: %d | 当前追踪IP: %d" % (
            elapsed, self.stats['lines'], self.stats['alerts'],
            len(self.detector.ip_events)
        ))

    def tail_follow(self):
        """实时监控日志文件（类似 tail -f）"""
        print("  监控文件: %s" % self.logfile)
        print("  等待新日志... (Ctrl+C 退出)\n")

        # 先跳到文件末尾
        try:
            with open(self.logfile, 'r', errors='ignore') as f:
                f.seek(0, 2)  # 跳到末尾
                pos = f.tell()
        except FileNotFoundError:
            print("  [!] 文件不存在: %s" % self.logfile)
            return

        try:
            while True:
                with open(self.logfile, 'r', errors='ignore') as f:
                    f.seek(pos)
                    new_lines = f.readlines()
                    if new_lines:
                        for line in new_lines:
                            self.process_line(line.strip())
                        pos = f.tell()

                    # 定期打印状态
                    if self.stats['lines'] > 0 and self.stats['lines'] % 100 == 0:
                        self.print_status()

                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n  [!] 监控停止")
            self.print_final_report()

    def print_final_report(self):
        """打印最终报告"""
        print("\n" + "=" * 60)
        print("  实时监控报告")
        print("=" * 60)
        print("  监控行数: %d" % self.stats['lines'])
        print("  告警次数: %d" % self.stats['alerts'])
        print("  追踪 IP:  %d" % len(self.detector.ip_events))

        if self.alerts:
            print("\n  告警汇总:")
            for a in self.alerts:
                print("  [%s] %s -> %s (%d 次)" % (
                    a['severity'], a['ip'], a['user'], a['count']))

        # 保存报告
        report_file = "log_monitor_%s.json" % time.strftime('%Y%m%d_%H%M%S')
        with open(report_file, 'w') as f:
            json.dump({
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'stats': self.stats,
                'alerts': self.alerts,
            }, f, indent=2, ensure_ascii=False)
        print("  报告已保存: %s" % report_file)
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description='Day5: 实时日志监控')
    parser.add_argument('logfile', help='日志文件路径')
    parser.add_argument('--type', default='auth', help='日志类型')
    parser.add_argument('--threshold', type=int, default=5, help='暴力破解阈值')
    parser.add_argument('--window', type=int, default=300, help='检测窗口(秒)')
    args = parser.parse_args()

    print("=" * 60)
    print("  实时日志监控 v2 - Day5 实战")
    print("  作者: YURM | 日期: 2026-05-23")
    print("=" * 60)

    monitor = LogMonitor(args.logfile, args.type)
    monitor.detector.threshold = args.threshold
    monitor.detector.window = args.window
    monitor.tail_follow()


if __name__ == "__main__":
    main()
