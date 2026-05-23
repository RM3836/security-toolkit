#!/usr/bin/env python3
"""
Day2 实战：SSH 批量管理工具
功能：
  1. 批量连接多台服务器执行命令
  2. 批量上传/下载文件
  3. 服务器资产清单管理
  4. 执行结果保存

用法：
  python3 ssh_manager.py exec "uname -a"           # 所有主机执行命令
  python3 ssh_manager.py exec "df -h" --tag web     # 指定分组执行
  python3 ssh_manager.py upload local.txt /tmp/     # 批量上传文件
  python3 ssh_manager.py download /var/log/syslog ./ # 批量下载文件
"""

import paramiko
import sys
import os
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ========== 服务器清单 ==========
# 格式: {host, port, user, password, tag(分组标签)}
SERVERS = [
    {
        "host": "127.0.0.1",
        "port": 2223,
        "user": "testuser",
        "password": "test123",
        "tag": "web"
    },
    {
        "host": "127.0.0.1",
        "port": 2224,
        "user": "admin",
        "password": "admin456",
        "tag": "db"
    },
]

MAX_WORKERS = 10  # 并发连接数
TIMEOUT = 10      # SSH 超时秒数
# ==============================


class SSHClient:
    """单台服务器的 SSH 操作封装"""

    def __init__(self, host, port, user, password):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.client = None

    def connect(self):
        """建立 SSH 连接"""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            hostname=self.host,
            port=self.port,
            username=self.user,
            password=self.password,
            timeout=TIMEOUT,
            allow_agent=False,
            look_for_keys=False
        )

    def execute(self, command):
        """执行命令，返回 (stdout, stderr, exit_code)"""
        if not self.client:
            self.connect()
        stdin, stdout, stderr = self.client.exec_command(command, timeout=30)
        exit_code = stdout.channel.recv_exit_status()
        return (
            stdout.read().decode('utf-8', errors='ignore').strip(),
            stderr.read().decode('utf-8', errors='ignore').strip(),
            exit_code
        )

    def upload(self, local_path, remote_path):
        """上传文件"""
        if not self.client:
            self.connect()
        sftp = self.client.open_sftp()
        try:
            # 如果 remote_path 是目录，自动拼接文件名
            try:
                stat = sftp.stat(remote_path)
                # 是目录，拼接文件名
                if not remote_path.endswith('/'):
                    remote_path = remote_path + '/'
                remote_path = remote_path + os.path.basename(local_path)
            except IOError:
                # 不是目录，直接用作目标路径
                pass
            sftp.put(local_path, remote_path)
            return True, "上传成功 -> %s" % remote_path
        except Exception as e:
            return False, str(e)
        finally:
            sftp.close()

    def download(self, remote_path, local_path):
        """下载文件"""
        if not self.client:
            self.connect()
        sftp = self.client.open_sftp()
        try:
            filename = os.path.basename(remote_path)
            dest = os.path.join(local_path, filename)
            sftp.get(remote_path, dest)
            return True, "下载到 %s" % dest
        except Exception as e:
            return False, str(e)
        finally:
            sftp.close()

    def close(self):
        if self.client:
            self.client.close()


def run_on_server(server, command):
    """在单台服务器上执行命令（线程任务）"""
    tag = server.get('tag', '')
    label = "%s@%s:%s [%s]" % (server['user'], server['host'], server['port'], tag)
    client = SSHClient(server['host'], server['port'], server['user'], server['password'])
    try:
        client.connect()
        stdout, stderr, exit_code = client.execute(command)
        return {
            'server': label,
            'host': server['host'],
            'status': 'success',
            'stdout': stdout,
            'stderr': stderr,
            'exit_code': exit_code
        }
    except Exception as e:
        return {
            'server': label,
            'host': server['host'],
            'status': 'error',
            'stdout': '',
            'stderr': str(e),
            'exit_code': -1
        }
    finally:
        client.close()


def upload_to_server(server, local_path, remote_path):
    """上传文件到单台服务器（线程任务）"""
    label = "%s@%s:%s" % (server['user'], server['host'], server['port'])
    client = SSHClient(server['host'], server['port'], server['user'], server['password'])
    try:
        client.connect()
        success, msg = client.upload(local_path, remote_path)
        return {'server': label, 'status': 'success' if success else 'error', 'message': msg}
    except Exception as e:
        return {'server': label, 'status': 'error', 'message': str(e)}
    finally:
        client.close()


def download_from_server(server, remote_path, local_path):
    """从单台服务器下载文件（线程任务）"""
    label = "%s@%s:%s" % (server['user'], server['host'], server['port'])
    client = SSHClient(server['host'], server['port'], server['user'], server['password'])
    try:
        client.connect()
        success, msg = client.download(remote_path, local_path)
        return {'server': label, 'status': 'success' if success else 'error', 'message': msg}
    except Exception as e:
        return {'server': label, 'status': 'error', 'message': str(e)}
    finally:
        client.close()


def filter_servers(tag=None):
    """按标签筛选服务器"""
    if tag:
        return [s for s in SERVERS if s.get('tag') == tag]
    return SERVERS


def batch_exec(servers, command):
    """批量执行命令"""
    print("\n  [*] 执行命令: %s" % command)
    print("  [*] 目标主机: %d 台\n" % len(servers))

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(run_on_server, s, command): s for s in servers}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)

            # 实时打印结果
            status_icon = "✓" if result['exit_code'] == 0 else "✗"
            print("  [%s] %s" % (status_icon, result['server']))
            if result['stdout']:
                for line in result['stdout'].split('\n')[:10]:
                    print("      %s" % line)
            if result['stderr']:
                print("      ERR: %s" % result['stderr'][:100])
            print()

    return results


def batch_upload(servers, local_path, remote_path):
    """批量上传文件"""
    print("\n  [*] 上传: %s -> %s" % (local_path, remote_path))
    print("  [*] 目标主机: %d 台\n" % len(servers))

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(upload_to_server, s, local_path, remote_path): s for s in servers}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            icon = "✓" if result['status'] == 'success' else "✗"
            print("  [%s] %s — %s" % (icon, result['server'], result['message']))

    return results


def batch_download(servers, remote_path, local_path):
    """批量下载文件"""
    os.makedirs(local_path, exist_ok=True)
    print("\n  [*] 下载: %s -> %s" % (remote_path, local_path))
    print("  [*] 目标主机: %d 台\n" % len(servers))

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(download_from_server, s, remote_path, local_path): s for s in servers}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            icon = "✓" if result['status'] == 'success' else "✗"
            print("  [%s] %s — %s" % (icon, result['server'], result['message']))

    return results


def save_results(results, action, command=""):
    """保存执行结果"""
    outfile = "ssh_%s_%s.json" % (action, time.strftime("%Y%m%d_%H%M%S"))
    output = {
        'action': action,
        'command': command,
        'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'total': len(results),
        'success': sum(1 for r in results if r.get('status') == 'success' or r.get('exit_code') == 0),
        'results': results
    }
    with open(outfile, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print("  结果已保存: %s" % outfile)
    return outfile


def main():
    print("=" * 55)
    print("  SSH 批量管理工具 - Day2 实战")
    print("  作者: YURM | 日期: 2026-05-20")
    print("=" * 55)

    if len(sys.argv) < 2:
        print("""
用法:
  执行命令:    python3 ssh_manager.py exec "uname -a"
  指定分组:    python3 ssh_manager.py exec "df -h" --tag web
  上传文件:    python3 ssh_manager.py upload local.txt /tmp/
  下载文件:    python3 ssh_manager.py download /var/log/syslog ./
  查看主机列表: python3 ssh_manager.py list
""")
        return

    action = sys.argv[1]

    # 解析 --tag 参数
    tag = None
    if '--tag' in sys.argv:
        tag_idx = sys.argv.index('--tag')
        tag = sys.argv[tag_idx + 1] if tag_idx + 1 < len(sys.argv) else None

    servers = filter_servers(tag)

    if not servers:
        print("  [!] 没有匹配的服务器 (tag=%s)" % tag)
        print("  当前服务器列表:" )
        for s in SERVERS:
            print("    %s:%s [%s]" % (s['host'], s['port'], s.get('tag', '')))
        return

    if action == 'list':
        print("\n  服务器清单:")
        print("  %-18s %-6s %-10s %-8s" % ("Host", "Port", "User", "Tag"))
        print("  " + "-" * 45)
        for s in SERVERS:
            print("  %-18s %-6s %-10s %-8s" % (
                s['host'], s['port'], s['user'], s.get('tag', '-')))

    elif action == 'exec':
        if len(sys.argv) < 3:
            print("  [!] 请指定要执行的命令")
            return
        command = sys.argv[2]
        results = batch_exec(servers, command)
        save_results(results, 'exec', command)

    elif action == 'upload':
        if len(sys.argv) < 4:
            print("  [!] 用法: upload <本地文件> <远程路径>")
            return
        results = batch_upload(servers, sys.argv[2], sys.argv[3])
        save_results(results, 'upload')

    elif action == 'download':
        if len(sys.argv) < 4:
            print("  [!] 用法: download <远程文件> <本地目录>")
            return
        results = batch_download(servers, sys.argv[2], sys.argv[3])
        save_results(results, 'download')

    else:
        print("  [!] 未知操作: %s" % action)


if __name__ == "__main__":
    main()
