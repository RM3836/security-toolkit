#!/usr/bin/env python3
"""
SSH 蜜罐模块 - 伪造 SSH 服务器，记录攻击者行为
作者: YURM | 日期: 2026-05-23

原理：
  - 使用 Paramiko 创建伪造的 SSH 服务器
  - 接受任意密码登录（记录所有尝试的密码）
  - 提供伪造的文件系统（假的 /etc/passwd、假配置文件）
  - 记录攻击者输入的每一条命令
"""

import os
import socket
import threading
import time
import uuid
import logging
from datetime import datetime

try:
    import paramiko
except ImportError:
    paramiko = None

from database import log_ssh_attack

logger = logging.getLogger("ssh_trap")

# 伪造的服务器 Banner
FAKE_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"

# 伪造的文件系统
FAKE_FILESYSTEM = {
    "/": "bin  boot  dev  etc  home  lib  opt  proc  root  sbin  srv  tmp  usr  var",
    "/etc": "passwd  shadow  hosts  hostname  resolv.conf  ssh  nginx  crontab",
    "/etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
admin:x:1000:1000:Admin User:/home/admin:/bin/bash
""",
    "/etc/shadow": "root:$6$rounds=656000$randomsalt$hashedpassword:19000:0:99999:7:::",
    "/etc/hosts": "127.0.0.1 localhost\n192.168.1.100 web-server\n192.168.1.101 db-server",
    "/etc/resolv.conf": "nameserver 8.8.8.8\nnameserver 8.8.4.4",
    "/etc/hostname": "prod-web-01",
    "/etc/nginx/nginx.conf": "user www-data;\nworker_processes 4;\npid /run/nginx.pid;\n...\nserver { listen 80; server_name example.com; }",
    "/etc/crontab": "*/5 * * * * root /opt/backup.sh\n0 3 * * * root /usr/bin/certbot renew",
    "/root/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHJwAAAADAQABAAABAQC...\n-----END OPENSSH PRIVATE KEY-----",
    "/root/.bash_history": "mysql -u root -p'S3cur3P@ss!'\nssh admin@192.168.1.101\ncat /etc/shadow\ndocker ps\napt install nginx",
    "/var/www/html/config.php": "<?php\n$db_host = \'192.168.1.101\';\n$db_user = \'webapp\';\n$db_pass = \'W3bApp@2026!\';\n$db_name = \'production\';",
    "/opt/backup.sh": "#!/bin/bash\nmysqldump -u root -p\'S3cur3P@ss!\' production > /backup/db_$(date +%Y%m%d).sql",
}

# 伪造命令响应
FAKE_COMMANDS = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "hostname": "prod-web-01",
    "uname -a": "Linux prod-web-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "cat /etc/os-release": 'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu',
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255",
    "ip addr": "2: eth0: <BROADCAST,MULTICAST,UP> inet 192.168.1.100/24",
    "ps aux": "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT COMMAND\nroot         1  0.0  0.1 169368 11200 ?        Ss   Jan01   0:05 /sbin/init\nroot       892  0.0  0.3 328412 28400 ?        Ss   Jan01   1:23 nginx: master\nwww-data   893  0.0  0.2 331204 18400 ?        S    Jan01   0:45 nginx: worker\nmysql     1024  0.1  2.1 1742560 172000 ?      Ssl  Jan01  12:34 /usr/sbin/mysqld",
    "netstat -tlnp": "Active Internet connections\nProto Recv-Q Send-Q Local Address    State  PID/name\ntcp   0   0  0.0.0.0:22      LISTEN  678/sshd\ntcp   0   0  0.0.0.0:80      LISTEN  892/nginx\ntcp   0   0  0.0.0.0:3306    LISTEN  1024/mysqld\ntcp   0   0  0.0.0.0:6379    LISTEN  1156/redis-server",
    "df -h": "Filesystem  Size  Used Avail Use% Mounted on\n/dev/sda1    50G   32G   16G  67% /\n/dev/sdb1   200G  145G   45G  77% /data",
    "free -m": "              total   used   free   shared  buff/cache  available\nMem:          7982    5842    412     256        1728       1640\nSwap:         2048     512    1536",
    "w": " 14:23:01 up 45 days,  3:12,  2 users,  load average: 0.15, 0.10, 0.05\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    192.168.1.50     14:20    0.00s  0.05s  0.01s w",
    "last": "root     pts/0   192.168.1.50  Mon May 23 14:20   still logged in\nadmin    pts/1   10.0.0.1       Sun May 22 03:12 - 04:30  (01:18)",
    "docker ps": "CONTAINER ID  IMAGE         STATUS       PORTS                  NAMES\na1b2c3d4e5f6  nginx:1.24    Up 45 days    0.0.0.0:80->80/tcp      web\nf6e5d4c3b2a1  mysql:8.0     Up 45 days    0.0.0.0:3306->3306/tcp  db",
    "mysql --version": "mysql  Ver 8.0.35-0ubuntu0.22.04.1 for Linux on x86_64",
    "nginx -v": "nginx version: nginx/1.24.0",
    "cat /proc/cpuinfo": "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu cores\t: 4",
    "ls -la /var/www/html/": "total 48\ndrwxr-xr-x 3 www-data www-data 4096 May 20 10:00 .\n-rw-r--r-- 1 www-data www-data  520 May 15 08:00 config.php\n-rw-r--r-- 1 www-data www-data 2048 May 18 12:00 index.php\n-rw-r--r-- 1 www-data www-data  256 May 10 09:00 robots.txt",
}


class SSHHoneypot(paramiko.ServerInterface if paramiko else object):
    """SSH 蜜罐服务器接口"""

    def __init__(self, client_addr, callback=None):
        self.client_addr = client_addr
        self.callback = callback  # 攻击事件回调
        self.session_id = str(uuid.uuid4())[:8]
        self.username = ""
        self.attempted_passwords = []

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """接受所有密码（记录尝试）"""
        self.username = username
        self.attempted_passwords.append(password)
        logger.info(f"[SSH] 登录尝试: {username}:{password} 来自 {self.client_addr[0]}")

        log_ssh_attack(
            src_ip=self.client_addr[0],
            src_port=self.client_addr[1],
            username=username,
            password=password,
            session_id=self.session_id
        )

        if self.callback:
            self.callback("ssh_login", {
                "ip": self.client_addr[0], "user": username, "pass": password
            })

        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def handle_ssh_client(client_sock, client_addr, callback=None):
    """处理 SSH 客户端连接"""
    trap = SSHHoneypot(client_addr, callback)

    try:
        # 加载或生成服务器密钥
        host_key_path = "honeypot_host_key"
        if os.path.exists(host_key_path):
            host_key = paramiko.RSAKey.from_private_key_file(host_key_path)
        else:
            host_key = paramiko.RSAKey.generate(2048)
            host_key.write_private_key_file(host_key_path)

        transport = paramiko.Transport(client_sock)
        transport.add_server_key(host_key)
        transport.local_version = FAKE_BANNER

        transport.start_server(server=trap)

        # 等待认证
        channel = transport.accept(30)
        if channel is None:
            transport.close()
            return

        # 发送欢迎信息
        welcome = (
            "\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/advantage\r\n\r\n"
            f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {client_addr[0]}\r\n"
        )
        channel.send(welcome)

        # 伪造 Shell 交互
        cwd = "/root"
        channel.send(f"root@prod-web-01:~# ")

        command_buffer = ""
        while True:
            try:
                data = channel.recv(1024)
                if not data:
                    break

                char = data.decode("utf-8", errors="ignore")

                for c in char:
                    if c in ("\r", "\n"):
                        cmd = command_buffer.strip()
                        if cmd:
                            # 记录命令
                            log_ssh_attack(
                                src_ip=client_addr[0], src_port=client_addr[1],
                                username=trap.username, password="",
                                command=cmd, session_id=trap.session_id
                            )
                            if callback:
                                callback("ssh_command", {
                                    "ip": client_addr[0], "command": cmd
                                })
                            logger.info(f"[SSH] 命令: {client_addr[0]} $ {cmd}")

                            # 处理命令
                            response = process_command(cmd, cwd)
                            if response == "__exit__":
                                channel.send("\r\n")
                                channel.close()
                                return
                            if cmd.startswith("cd "):
                                cwd = response[1]  # new cwd
                                response = response[0]

                            channel.send(f"\r\n{response}\r\n")

                        command_buffer = ""
                        channel.send(f"root@prod-web-01:{cwd.replace('/root', '~')}# ")

                    elif c == "\x7f":  # Backspace
                        if command_buffer:
                            command_buffer = command_buffer[:-1]
                            channel.send("\b \b")
                    elif c == "\x03":  # Ctrl+C
                        channel.send("^C\r\n")
                        command_buffer = ""
                        channel.send(f"root@prod-web-01:{cwd.replace('/root', '~')}# ")
                    else:
                        command_buffer += c
                        channel.send(c)

            except Exception:
                break

    except Exception as e:
        logger.error(f"[SSH] 处理错误: {e}")
    finally:
        try:
            client_sock.close()
        except:
            pass


def process_command(cmd, cwd="/root"):
    """处理攻击者输入的命令，返回伪造响应"""
    # cd 命令
    if cmd.startswith("cd "):
        path = cmd[3:].strip()
        if path == "~" or path == "/root":
            return ("", "/root")
        if path == "/":
            return ("", "/")
        if path == "..":
            new_cwd = "/".join(cwd.split("/")[:-1]) or "/"
            return ("", new_cwd)
        full_path = path if path.startswith("/") else f"{cwd}/{path}"
        if full_path in FAKE_FILESYSTEM:
            return ("", full_path)
        return (f"bash: cd: {path}: No such file or directory", cwd)

    # exit
    if cmd in ("exit", "logout", "quit"):
        return "__exit__"

    # cat 命令
    if cmd.startswith("cat "):
        path = cmd[4:].strip()
        if not path.startswith("/"):
            path = f"{cwd}/{path}"
        if path in FAKE_FILESYSTEM:
            return FAKE_FILESYSTEM[path]
        return f"cat: {cmd[4:].strip()}: No such file or directory"

    # ls 命令
    if cmd.startswith("ls"):
        target = cwd
        if len(cmd) > 2:
            arg = cmd[2:].strip().lstrip("-la").strip()
            if arg:
                target = arg if arg.startswith("/") else f"{cwd}/{arg}"
        if target in FAKE_FILESYSTEM:
            return FAKE_FILESYSTEM[target]
        return f"ls: cannot access \'{target}\': No such file or directory"

    # 预定义命令响应
    if cmd in FAKE_COMMANDS:
        return FAKE_COMMANDS[cmd]

    # 带参数的部分匹配
    for pattern, response in FAKE_COMMANDS.items():
        if cmd.startswith(pattern.split()[0]):
            return response

    return f"bash: {cmd}: command not found"


def start_ssh_honeypot(port=2222, callback=None):
    """启动 SSH 蜜罐服务器"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(100)

    logger.info(f"[SSH] 蜜罐启动在端口 {port}")
    print(f"  [*] SSH 蜜罐监听 0.0.0.0:{port}")
    print(f"  [*] Banner: {FAKE_BANNER}")

    while True:
        try:
            client_sock, client_addr = server.accept()
            logger.info(f"[SSH] 新连接: {client_addr[0]}:{client_addr[1]}")
            t = threading.Thread(target=handle_ssh_client, args=(client_sock, client_addr, callback))
            t.daemon = True
            t.start()
        except Exception as e:
            logger.error(f"[SSH] 接受连接错误: {e}")
