#!/usr/bin/env python3
"""
Day7 进阶C：蜜罐 + 威胁情报系统
主动诱捕攻击者，记录行为，生成画像
作者: YURM | 日期: 2026-05-23

运行: python3 honeypot.py --ssh-port 2222 --http-port 8080 --dashboard-port 5000
"""

import os
import sys
import argparse
import threading
import logging
import json
import time
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler("honeypot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("honeypot")

from database import init_db, get_stats, log_ssh_attack, log_http_attack
from ssh_trap import start_ssh_honeypot
from http_trap import start_http_honeypot
from threat_intel import enrich_attacker_profiles, lookup_ip

# 全局事件列表（WebSocket 推送用）
attack_events = []
event_lock = threading.Lock()


def attack_callback(event_type, data):
    """攻击事件回调 - 所有蜜罐模块的事件汇总"""
    event = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "data": data
    }
    with event_lock:
        attack_events.append(event)
        if len(attack_events) > 500:
            attack_events.pop(0)

    # 彩色终端输出
    colors = {
        "ssh_login": "\033[91m[SSH登录]\033[0m",
        "ssh_command": "\033[93m[SSH命令]\033[0m",
        "http_access": "\033[96m[HTTP访问]\033[0m",
        "login_attempt": "\033[91m[登录尝试]\033[0m",
    }
    prefix = colors.get(event_type, "[事件]")
    ip = data.get("ip", "unknown")

    if event_type == "ssh_login":
        print(f"  {prefix} {ip}  用户: {data.get('user')}  密码: {data.get('pass')}")
    elif event_type == "ssh_command":
        print(f"  {prefix} {ip}  $ {data.get('command')}")
    elif event_type == "http_access":
        print(f"  {prefix} {ip}  {data.get('method')} {data.get('path')}  ({data.get('type')})")
    else:
        print(f"  {prefix} {ip}  {json.dumps(data, ensure_ascii=False)[:100]}")


def start_dashboard(port=5000):
    """启动监控仪表盘"""
    from flask import Flask, render_template_string, jsonify
    from flask_socketio import SocketIO

    app = Flask(__name__)
    app.secret_key = "honeypot-dashboard"
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

    DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-CN" data-bs-theme="dark">
<head>
    <meta charset="UTF-8"><title>Honeypot Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
    <style>
        body{background:#0a101c;color:#e0e0e0}
        .card{background:#111827;border:1px solid #1e3a5f;border-radius:10px}
        .stat-n{font-size:36px;font-weight:bold;color:#00d4aa}
        .ev-feed{max-height:500px;overflow-y:auto;font-family:monospace;font-size:13px}
        .ev-item{padding:6px 10px;margin-bottom:3px;border-radius:4px;background:#1a2332}
        .sev-CRITICAL{color:#da3633}.sev-HIGH{color:#ff6b6b}.sev-MEDIUM{color:#d29a22}.sev-LOW{color:#2ea043}
        .pulse{animation:pulse 2s infinite}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
    </style>
</head>
<body>
<div class="container-fluid mt-3">
    <h4 style="color:#00d4aa">🍯 蜜罐威胁情报监控中心 <span class="pulse" style="color:#da3633;font-size:14px">● LIVE</span></h4>
    <div class="row mt-3 mb-3">
        <div class="col-md-3"><div class="card p-3 text-center"><div class="stat-n" id="sshCount">0</div><div style="color:#8c9db5">SSH 攻击次数</div></div></div>
        <div class="col-md-3"><div class="card p-3 text-center"><div class="stat-n" id="httpCount">0</div><div style="color:#8c9db5">HTTP 攻击次数</div></div></div>
        <div class="col-md-3"><div class="card p-3 text-center"><div class="stat-n" id="ipCount">0</div><div style="color:#8c9db5">独立攻击者 IP</div></div></div>
        <div class="col-md-3"><div class="card p-3 text-center"><div class="stat-n" id="eventCount">0</div><div style="color:#8c9db5">实时事件数</div></div></div>
    </div>
    <div class="row">
        <div class="col-md-7">
            <div class="card p-3">
                <h6 style="color:#00d4aa">📡 实时攻击流</h6>
                <div class="ev-feed" id="eventFeed"></div>
            </div>
        </div>
        <div class="col-md-5">
            <div class="card p-3 mb-3">
                <h6 style="color:#da3633">🎯 攻击者排行榜</h6>
                <div id="attackerTable" style="font-size:13px"></div>
            </div>
            <div class="card p-3">
                <h6 style="color:#d29a22">🔑 最近 SSH 尝试</h6>
                <div id="sshTable" style="font-size:12px;max-height:200px;overflow-y:auto"></div>
            </div>
        </div>
    </div>
</div>
<script>
    const socket = io();
    let evCount = 0;
    socket.on('attack_event', function(d) {
        evCount++;
        document.getElementById('eventCount').textContent = evCount;
        const feed = document.getElementById('eventFeed');
        const item = document.createElement('div');
        item.className = 'ev-item';
        item.innerHTML = '<span style="color:#00d4aa">' + d.time + '</span> <strong>' + d.type + '</strong> ' + d.ip + ' ' + (d.detail||'');
        feed.insertBefore(item, feed.firstChild);
        if (feed.children.length > 100) feed.removeChild(feed.lastChild);
    });
    function refresh() {
        fetch('/api/stats').then(r=>r.json()).then(d=>{
            document.getElementById('sshCount').textContent = d.ssh_attacks;
            document.getElementById('httpCount').textContent = d.http_attacks;
            document.getElementById('ipCount').textContent = d.unique_attackers;
            let html = '<table class="table table-sm"><tr><th>IP</th><th>次数</th><th>等级</th><th>国家</th></tr>';
            (d.attackers||[]).forEach(a=>{
                html += '<tr><td>'+a.ip+'</td><td>'+a.count+'</td><td><span class="sev-'+a.severity+'">'+a.severity+'</span></td><td>'+(a.country||'?')+'</td></tr>';
            });
            document.getElementById('attackerTable').innerHTML = html + '</table>';
            let ssh = '';
            (d.recent_ssh||[]).forEach(s=>{ ssh += '<div>' + s.time + ' <strong>' + s.user + '</strong> : ' + s.pass + ' @ ' + s.ip + '</div>'; });
            document.getElementById('sshTable').innerHTML = ssh;
        });
    }
    setInterval(refresh, 5000);
    refresh();
</script>
</body>
</html>"""

    @app.route("/")
    def dashboard():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/stats")
    def api_stats():
        return jsonify(get_stats())

    @app.route("/api/events")
    def api_events():
        with event_lock:
            return jsonify(attack_events[-50:])

    # 后台推送攻击事件
    def push_events():
        last = 0
        while True:
            with event_lock:
                current = len(attack_events)
                if current > last:
                    for ev in attack_events[last:]:
                        socketio.emit("attack_event", {
                            "time": ev["time"], "type": ev["type"],
                            "ip": ev["data"].get("ip", ""),
                            "detail": str(ev["data"])[:100]
                        })
                    last = current
            time.sleep(1)

    threading.Thread(target=push_events, daemon=True).start()

    logger.info(f"[Dashboard] 仪表盘启动在端口 {port}")
    print(f"  [*] 监控仪表盘: http://localhost:{port}")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)


def main():
    """主入口"""
    parser = argparse.ArgumentParser(description="Day7 进阶C: 蜜罐 + 威胁情报系统")
    parser.add_argument("--ssh-port", type=int, default=2222, help="SSH 蜜罐端口 (默认 2222)")
    parser.add_argument("--http-port", type=int, default=8080, help="HTTP 蜜罐端口 (默认 8080)")
    parser.add_argument("--dashboard-port", type=int, default=5000, help="监控仪表盘端口 (默认 5000)")
    args = parser.parse_args()

    print("=" * 60)
    print("  Day7 进阶C: 蜜罐 + 威胁情报系统")
    print("  作者: YURM | 日期: 2026-05-23")
    print("=" * 60)
    print()
    print("  🍯 蜜罐服务:")
    print(f"  [*] SSH 蜜罐:    0.0.0.0:{args.ssh_port}  (伪造 OpenSSH 8.9)")
    print(f"  [*] HTTP 蜜罐:   0.0.0.0:{args.http_port}  (WordPress/phpMyAdmin)")
    print(f"  [*] 监控面板:    0.0.0.0:{args.dashboard_port}")
    print()
    print("  ⚠️  请确保防火墙已放行以上端口")
    print("  ⚠️  仅用于安全研究和教学目的")
    print("=" * 60)
    print()

    # 初始化数据库
    init_db()

    # 启动 SSH 蜜罐（后台线程）
    ssh_thread = threading.Thread(
        target=start_ssh_honeypot,
        args=(args.ssh_port, attack_callback),
        daemon=True
    )
    ssh_thread.start()

    # 启动 HTTP 蜜罐（后台线程）
    http_thread = threading.Thread(
        target=start_http_honeypot,
        args=(args.http_port, attack_callback),
        daemon=True
    )
    http_thread.start()

    # 启动威胁情报丰富（后台定时）
    def enrich_loop():
        while True:
            try:
                enrich_attacker_profiles()
            except Exception as e:
                logger.error(f"[威胁情报] 丰富失败: {e}")
            time.sleep(300)  # 每5分钟更新一次

    threading.Thread(target=enrich_loop, daemon=True).start()

    # 主线程运行仪表盘
    start_dashboard(args.dashboard_port)


if __name__ == "__main__":
    main()
