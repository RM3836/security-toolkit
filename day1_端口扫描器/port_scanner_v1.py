#!/usr/bin/env python3
"""
Day1 实战：TCP 端口扫描器 v1（单线程版）
原理：尝试对目标IP的每个端口发起 TCP 连接
  - 连接成功 = 端口开放
  - 连接拒绝 = 端口关闭
  - 超时      = 端口被过滤（防火墙）
"""

import socket
import sys
import time

def scan_port(ip, port, timeout=1):
    """
    扫描单个端口
    返回: 'open' / 'closed' / 'filtered'
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建TCP套接字
    sock.settimeout(timeout)  # 设置超时时间，别卡死
    try:
        result = sock.connect_ex((ip, port))  # connect_ex 不抛异常，返回错误码
        if result == 0:
            return 'open'
        else:
            return 'closed'
    except socket.timeout:
        return 'filtered'  # 超时=被防火墙过滤了
    except Exception:
        return 'error'
    finally:
        sock.close()  # 记得关连接，不然会耗尽资源


def main():
    # ========== 配置区 ==========
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port_range = range(1, 1025)  # 扫描前1024个常用端口
    # ============================

    print(f"{'='*50}")
    print(f"  TCP 端口扫描器 v1 - Day1 实战")
    print(f"  目标: {target}")
    print(f"  端口范围: {port_range.start}-{port_range.stop-1}")
    print(f"{'='*50}")

    open_ports = []
    start_time = time.time()

    for port in port_range:
        status = scan_port(target, port)
        if status == 'open':
            open_ports.append(port)
            # 实时打印发现的开放端口
            try:
                service = socket.getservbyport(port)  # 查端口对应的服务名
            except:
                service = "unknown"
            print(f"  [+] {port:>5}/tcp  OPEN  ({service})")

    elapsed = time.time() - start_time

    print(f"\n{'='*50}")
    print(f"  扫描完成！")
    print(f"  发现 {len(open_ports)} 个开放端口")
    print(f"  耗时: {elapsed:.2f} 秒")
    if open_ports:
        print(f"  开放端口: {open_ports}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
