# Day7 进阶C：蜜罐 + 威胁情报系统

## 简介
主动诱捕攻击者并分析行为的安全系统。包含 SSH 蜜罐、HTTP 蜜罐、威胁情报、实时监控仪表盘。

## 功能
- 🍯 SSH 蜜罐（伪造 OpenSSH 服务器，记录密码和命令）
- 🌐 HTTP 蜜罐（伪造 WordPress/phpMyAdmin 登录页）
- 🌍 威胁情报（IP 地理定位、攻击者画像）
- 📊 实时仪表盘（WebSocket 攻击流推送）
- 🎯 攻击者排行榜（按攻击次数/严重级别排序）

## 运行
```bash
pip install -r requirements.txt
python3 honeypot.py --ssh-port 2222 --http-port 8080 --dashboard-port 5000
```

### 测试 SSH 蜜罐
```bash
ssh root@localhost -p 2222    # 任意密码可登录
```

### 测试 HTTP 蜜罐
```bash
curl http://localhost:8080/wp-login.php
curl http://localhost:8080/.env
```

## 技术栈
- Python 3.10+ / Paramiko / Flask / Flask-SocketIO
- SQLite / WebSocket / Bootstrap 5

## 作者
YURM | 2026-05-23
