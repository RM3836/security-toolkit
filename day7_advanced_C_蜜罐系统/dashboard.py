"""
dashboard.py - 蜜罐威胁情报仪表盘
===================================
提供Web仪表盘界面和WebSocket实时攻击推送功能。
端口8080，暗色主题，显示攻击统计、攻击者档案和实时攻击日志。

作者: YURM
日期: 2026-05-23
"""

import threading
from flask import Flask, render_template
from flask_socketio import SocketIO

from database import (
    init_db,
    get_recent_attacks,
    get_attacker_profiles,
    get_stats,
    get_command_frequency,
)


# 仪表盘Flask应用
app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'honeypot-dashboard-secret-2026'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')


@app.route('/')
def index():
    """
    仪表盘首页
    显示攻击统计、最近攻击、攻击者档案和命令频率分析
    """
    stats = get_stats()
    recent_attacks = get_recent_attacks(limit=50)
    profiles = get_attacker_profiles()
    command_freq = get_command_frequency()

    return render_template(
        'dashboard.html',
        stats=stats,
        recent_attacks=recent_attacks,
        profiles=profiles,
        command_freq=command_freq,
    )


def emit_attack(attack_data):
    """
    通过WebSocket广播新攻击事件给所有连接的客户端

    参数:
        attack_data: 攻击数据字典
    """
    try:
        socketio.emit('new_attack', attack_data)
    except Exception as e:
        print(f"[仪表盘] WebSocket推送失败: {e}")


def start_dashboard(port=8080):
    """
    启动仪表盘Web服务器

    参数:
        port: 监听端口，默认8080
    """
    print(f"[仪表盘] 威胁情报仪表盘启动于 http://0.0.0.0:{port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    init_db()
    start_dashboard()
