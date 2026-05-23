#!/usr/bin/env python3
"""
扫描引擎 - 封装 Day1-6 的核心扫描功能
作者: YURM | 日期: 2026-05-23
"""

import socket
import threading
import time
import re
import json
import sqlite3
from datetime import datetime
from collections import Counter

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    requests = None


class PortScanner:
    """端口扫描器 - TCP Connect Scan"""

    # 常见端口服务映射
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    }

    def scan(self, target, ports=None, timeout=1, threads=100):
        """执行端口扫描"""
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())

        open_ports = []
        lock = threading.Lock()
        results = []

        def _scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = self.COMMON_PORTS.get(port, "Unknown")
                    # 尝试抓取 banner
                    banner = ""
                    try:
                        sock.settimeout(2)
                        sock.send(bHEAD/1.1\r\n\r\n".encode())
                        banner = sock.recv(256).decode(errors='ignore').strip()[:100]
                    except:
                        pass
                    with lock:
                        results.append({
                            "port": port,
                            "service": service,
                            "state": "open",
                            "banner": banner
                        })
                sock.close()
            except:
                pass

        # 多线程扫描
        thread_list = []
        for port in ports:
            t = threading.Thread(target=_scan_port, args=(port,))
            thread_list.append(t)
            t.start()
            if len(thread_list) >= threads:
                for th in thread_list:
                    th.join()
                thread_list = []

        for th in thread_list:
            th.join()

        results.sort(key=lambda x: x["port"])
        return {
            "target": target,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_ports": len(ports),
            "open_ports": len(results),
            "results": results
        }


class WebScanner:
    """Web 漏洞扫描器"""

    def scan(self, target_url):
        """执行 Web 扫描"""
        if not requests:
            return {"error": "requests 库未安装"}

        findings = []
        target_url = target_url.rstrip("/")

        # 信息收集
        try:
            resp = requests.get(target_url, timeout=10, verify=False,
                              headers={"User-Agent": "SecurityScanner/1.0"})
            findings.append({
                "severity": "INFO", "category": "状态码",
                "detail": str(resp.status_code)
            })

            # 安全头检测
            security_headers = {
                "X-Frame-Options": "点击劫持防护",
                "X-Content-Type-Options": "MIME嗅探防护",
                "Content-Security-Policy": "CSP策略",
                "Strict-Transport-Security": "HSTS",
            }
            for header, desc in security_headers.items():
                if header not in resp.headers:
                    findings.append({
                        "severity": "LOW", "category": "缺少安全头",
                        "detail": f"{header} ({desc})"
                    })

            # 技术栈泄露
            if "X-Powered-By" in resp.headers:
                findings.append({
                    "severity": "MEDIUM", "category": "技术栈泄露",
                    "detail": resp.headers["X-Powered-By"]
                })

        except Exception as e:
            findings.append({"severity": "ERROR", "category": "连接失败", "detail": str(e)})
            return {"findings": findings}

        # 目录扫描
        sensitive_paths = [
            (".env", "HIGH"), (".git/HEAD", "HIGH"), ("robots.txt", "LOW"),
            ("admin/", "MEDIUM"), ("phpmyadmin/", "MEDIUM"), ("wp-admin/", "MEDIUM"),
            (".htaccess", "LOW"), ("backup.sql", "HIGH"), ("config.php", "HIGH"),
        ]
        for path, severity in sensitive_paths:
            try:
                r = requests.get(f"{target_url}/{path}", timeout=5, verify=False,
                               allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 50:
                    findings.append({
                        "severity": severity, "category": "目录发现",
                        "detail": f"{path} (HTTP {r.status_code})"
                    })
            except:
                pass
            time.sleep(0.1)

        # XSS 反射检测
        xss_payload = "<script>alert(1)</script>"
        try:
            r = requests.get(f"{target_url}?q={xss_payload}", timeout=5, verify=False)
            if xss_payload in r.text:
                findings.append({
                    "severity": "HIGH", "category": "XSS反射",
                    "detail": "参数 q 反射了 XSS payload"
                })
        except:
            pass

        severity_count = Counter(f["severity"] for f in findings)
        return {
            "target": target_url,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": len(findings),
            "summary": dict(severity_count),
            "findings": findings
        }


class LogAnalyzer:
    """日志分析器"""

    FAILED_LOGIN_RE = re.compile(
        r'(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (\S+) from (\S+)'
    )
    INVALID_USER_RE = re.compile(
        r'(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Invalid user (\S+) from (\S+)'
    )

    def analyze(self, log_content):
        """分析日志内容（字符串）"""
        failed_logins = []
        ip_counter = Counter()
        user_counter = Counter()

        for line in log_content.split("\n"):
            m = self.FAILED_LOGIN_RE.search(line)
            if m:
                failed_logins.append({"time": m.group(1), "user": m.group(2), "ip": m.group(3)})
                ip_counter[m.group(3)] += 1
                user_counter[m.group(2)] += 1
                continue

            m = self.INVALID_USER_RE.search(line)
            if m:
                ip_counter[m.group(3)] += 1
                user_counter[m.group(2)] += 1

        # 暴力破解检测
        brute_force = []
        for ip, count in ip_counter.most_common(10):
            if count >= 5:
                brute_force.append({
                    "ip": ip, "failures": count,
                    "severity": "HIGH" if count > 20 else "MEDIUM"
                })

        return {
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_failed": len(failed_logins),
            "top_ips": dict(ip_counter.most_common(10)),
            "top_users": dict(user_counter.most_common(10)),
            "brute_force_alerts": brute_force,
            "recent_failures": failed_logins[-20:]
        }


class IDSEngine:
    """入侵检测引擎"""

    # 检测规则
    ATTACK_PATTERNS = {
        "SQL注入": re.compile(r"(union\s+select|or\s+1=1|drop\s+table|--\s*$|'\s+or)", re.I),
        "XSS攻击": re.compile(r"(<script|onerror=|onload=|javascript:)", re.I),
        "路径遍历": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow)", re.I),
        "命令注入": re.compile(r"(;\s*cat|\|\s*ls|`whoami`|\$\(.*\))", re.I),
        "扫描器UA": re.compile(r"(nikto|sqlmap|nmap|masscan|zgrab|dirbuster)", re.I),
    }

    def detect(self, log_lines):
        """检测日志中的攻击行为"""
        alerts = []
        for line in log_lines:
            for attack_type, pattern in self.ATTACK_PATTERNS.items():
                if pattern.search(line):
                    alerts.append({
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "type": attack_type,
                        "severity": "HIGH",
                        "detail": line[:200]
                    })
                    break

        type_counter = Counter(a["type"] for a in alerts)
        return {
            "detection_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_alerts": len(alerts),
            "alert_types": dict(type_counter),
            "alerts": alerts[-50:]
        }
