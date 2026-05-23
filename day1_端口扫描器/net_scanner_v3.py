#!/usr/bin/env python3
"""
Day1 完整作品：网络探测器 v3
功能：
  1. 子网存活主机发现（ping sweep）
  2. 多线程端口扫描
  3. 服务 banner 抓取
  4. 结果保存到文件
"""

import socket
import subprocess
import sys
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========== 配置 ==========
MAX_THREADS = 200
TIMEOUT = 0.5
# ===========================

def ping_host(ip):
    """ping 检测主机是否存活"""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, timeout=2
        )
        return result.returncode == 0
    except:
        return False


def scan_port(ip, port):
    """扫描单个端口"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            banner = grab_banner(sock)
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            return (port, 'OPEN', service, banner)
        return (port, 'closed', '', '')
    except:
        return (port, 'error', '', '')
    finally:
        sock.close()


def grab_banner(sock):
    """抓取服务 banner"""
    try:
        sock.settimeout(1)
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors='ignore').strip()
        return banner.split('\n')[0][:80]
    except:
        return ""


def discover_hosts(subnet):
    """发现子网内存活主机"""
    print("\n  [*] 正在发现存活主机...")
    print("  子网: %s.0/24\n" % subnet)

    alive_hosts = []
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {}
        for i in range(1, 255):
            ip = "%s.%d" % (subnet, i)
            futures[pool.submit(ping_host, ip)] = ip

        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                alive_hosts.append(ip)
                print("  [+] 存活: %s" % ip)

    print("\n  [*] 发现 %d 台存活主机" % len(alive_hosts))
    return sorted(alive_hosts, key=lambda x: int(x.split('.')[-1]))


def scan_host(ip, ports):
    """扫描单台主机的所有端口"""
    open_ports = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
        futures = {pool.submit(scan_port, ip, p): p for p in ports}
        for future in as_completed(futures):
            port, status, service, banner = future.result()
            if status == 'OPEN':
                open_ports.append({
                    'port': port,
                    'service': service,
                    'banner': banner
                })
    return sorted(open_ports, key=lambda x: x['port'])


def main():
    # ========== 解析参数 ==========
    if len(sys.argv) < 2:
        print("用法:")
        print("  扫描单个主机:  python3 %s 127.0.0.1" % sys.argv[0])
        print("  扫描整个子网:  python3 %s 10.97.48 --discover" % sys.argv[0])
        print("  指定端口范围:  python3 %s 127.0.0.1 1-1024" % sys.argv[0])
        print("  指定端口列表:  python3 %s 127.0.0.1 22,80,443,3000" % sys.argv[0])
        sys.exit(1)

    target = sys.argv[1]
    discover_mode = '--discover' in sys.argv

    # 常见端口列表
    default_ports = [21,22,23,25,53,80,110,111,135,139,143,161,389,443,
                     445,465,514,587,636,993,995,1080,1433,1521,1723,
                     2049,2181,2375,2376,3000,3306,3389,4443,5432,5900,
                     5984,6379,6443,7001,8000,8080,8443,8888,9000,9090,
                     9200,9300,11211,27017]

    # 解析端口参数
    ports = default_ports
    for arg in sys.argv[2:]:
        if arg == '--discover':
            continue
        if '-' in arg:
            start, end = arg.split('-')
            ports = list(range(int(start), int(end) + 1))
        elif ',' in arg:
            ports = [int(p) for p in arg.split(',')]

    # ========== 开始扫描 ==========
    print("=" * 55)
    print("  网络探测器 v3 - Day1 完整作品")
    print("  作者: YURM | 日期: 2026-05-20")
    print("=" * 55)

    all_results = {}
    start_time = time.time()

    if discover_mode:
        # 子网发现模式
        hosts = discover_hosts(target)
        if not hosts:
            print("  [!] 未发现存活主机")
            return
        print("\n  [*] 开始逐台扫描端口...\n")
        for host in hosts:
            print("  --- %s ---" % host)
            open_ports = scan_host(host, ports)
            all_results[host] = open_ports
            for p in open_ports:
                banner_str = " | %s" % p['banner'][:40] if p['banner'] else ""
                print("  [+] %5d/tcp  %s  (%s)%s" % (
                    p['port'], 'OPEN', p['service'], banner_str))
            if not open_ports:
                print("  [-] 无开放端口")
    else:
        # 单主机模式
        print("\n  目标: %s | 端口数: %d\n" % (target, len(ports)))
        open_ports = scan_host(target, ports)
        all_results[target] = open_ports
        for p in open_ports:
            banner_str = " | %s" % p['banner'][:50] if p['banner'] else ""
            print("  [+] %5d/tcp  OPEN  (%s)%s" % (
                p['port'], p['service'], banner_str))

    elapsed = time.time() - start_time

    # ========== 汇总 ==========
    total_open = sum(len(v) for v in all_results.values())
    print("\n" + "=" * 55)
    print("  扫描完成！")
    print("  主机数: %d | 开放端口总数: %d | 耗时: %.2fs" % (
        len(all_results), total_open, elapsed))
    print("=" * 55)

    # 保存结果到 JSON 文件
    outfile = "scan_%s_%s.json" % (target.replace('.', '_'), 
               time.strftime("%Y%m%d_%H%M%S"))
    output = {
        'target': target,
        'scan_time': time.strftime("%Y-%m-%d %H:%M:%S"),
        'elapsed': round(elapsed, 2),
        'results': all_results
    }
    with open(outfile, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print("\n  结果已保存: %s" % outfile)


if __name__ == "__main__":
    main()
