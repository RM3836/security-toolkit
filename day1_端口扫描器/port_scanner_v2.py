#!/usr/bin/env python3
"""
Day1 实战：TCP 端口扫描器 v2（多线程版）
改进：用线程池并发扫描，速度提升几十倍
"""

import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========== 配置 ==========
MAX_THREADS = 200       # 并发线程数
TIMEOUT = 0.5           # 超时秒数，越小越快但可能漏报
# ===========================

def scan_port(ip, port):
    """扫描单个端口，返回 (端口号, 状态)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            # 尝试抓 banner（版本信息）
            banner = grab_banner(sock)
            return (port, 'OPEN', service, banner)
        return (port, 'closed', '', '')
    except socket.timeout:
        return (port, 'filtered', '', '')
    except:
        return (port, 'error', '', '')
    finally:
        sock.close()


def grab_banner(sock):
    """尝试获取服务 banner（版本信息）"""
    try:
        sock.settimeout(1)
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors='ignore').strip()
        # 只取第一行
        return banner.split('\n')[0][:80]
    except:
        return ""


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"

    # 解析端口范围：支持 "1-1024" 或 "22,80,443,3000" 或 "top100"
    if len(sys.argv) > 2:
        port_arg = sys.argv[2]
        if '-' in port_arg:
            start, end = port_arg.split('-')
            ports = range(int(start), int(end) + 1)
        elif ',' in port_arg:
            ports = [int(p) for p in port_arg.split(',')]
        else:
            ports = [int(port_arg)]
    else:
        # 默认：Top 100 常见端口
        ports = [21,22,23,25,53,80,110,111,135,139,143,161,389,443,
                 445,465,514,587,636,993,995,1080,1433,1521,1723,
                 2049,2181,2375,2376,3000,3306,3389,4443,5432,5900,
                 5984,6379,6443,7001,8000,8080,8443,8888,9000,9090,
                 9200,9300,11211,27017]

    print("=" * 55)
    print("  TCP 端口扫描器 v2 - 多线程版")
    print("  目标: %s" % target)
    print("  线程数: %d | 超时: %ss" % (MAX_THREADS, TIMEOUT))
    print("  端口数: %d" % len(list(ports) if hasattr(ports, '__len__') else ports))
    print("=" * 55)

    open_ports = []
    start_time = time.time()

    # 核心：线程池并发扫描
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
        # 提交所有扫描任务
        futures = {pool.submit(scan_port, target, p): p for p in ports}

        # as_completed 谁先完成就先处理谁
        for future in as_completed(futures):
            port, status, service, banner = future.result()
            if status == 'OPEN':
                open_ports.append((port, service, banner))
                line = "  [+] %5d/tcp  OPEN  (%s)" % (port, service)
                if banner:
                    line += " | %s" % banner[:50]
                print(line)

    elapsed = time.time() - start_time

    # 汇总
    print()
    print("=" * 55)
    print("  扫描完成！")
    print("  发现 %d 个开放端口" % len(open_ports))
    print("  耗时: %.2f 秒" % elapsed)
    print("=" * 55)

    if open_ports:
        print()
        print("  端口      服务        Banner")
        print("  " + "-" * 50)
        for port, service, banner in sorted(open_ports):
            print("  %-9d %-11s %s" % (port, service, banner[:40] if banner else "-"))


if __name__ == "__main__":
    main()
