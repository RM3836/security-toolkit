#!/usr/bin/env python3
"""
Day7 进阶A：Web 安全仪表盘
Flask + SocketIO 实时安全监控面板
作者: YURM | 日期: 2026-05-23

运行: python3 app.py
访问: http://localhost:5000
"""

import os
import json
import sqlite3
import time
import threading
from datetime import datetime
from functools import wraps

from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, session, flash)
from flask_socketio import SocketIO, emit

from scanner_engine import PortScanner, WebScanner, LogAnalyzer, IDSEngine

# ===== 初始化 =====
app = Flask(__name__)
app.secret_key = "autoops-security-dashboard-2026"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# 扫描引擎实例
port_scanner = PortScanner()
web_scanner = WebScanner()
log_analyzer = LogAnalyzer()
ids_engine = IDSEngine()

DB_PATH = "security_dashboard.db"


# ===== 数据库 =====
def init_db():
    """初始化 SQLite 数据库"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT NOT NULL,
        target TEXT NOT NULL,
        result_json TEXT NOT NULL,
        findings_count INTEGER DEFAULT 0,
        severity_high INTEGER DEFAULT 0,
        severity_medium INTEGER DEFAULT 0,
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT NOT NULL,
        source TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()
    conn.close()


def save_scan(scan_type, target, result):
    """保存扫描结果到数据库"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    findings_count = result.get("total_findings", result.get("open_ports", 0))
    severity_high = result.get("summary", {}).get("HIGH", 0)
    severity_medium = result.get("summary", {}).get("MEDIUM", 0)
    c.execute(
        "INSERT INTO scan_history (scan_type, target, result_json, findings_count, severity_high, severity_medium) VALUES (?,?,?,?,?,?)",
        (scan_type, target, json.dumps(result, ensure_ascii=False), findings_count, severity_high, severity_medium)
    )
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id


def save_alert(level, source, message):
    """保存告警"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO alerts (level, source, message) VALUES (?,?,?)", (level, source, message))
    conn.commit()
    conn.close()


# ===== 认证 =====
def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ===== 路由 =====
@app.route("/login", methods=["GET", "POST"])
def login():
    """登录页面"""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == "admin" and password == "admin123":
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))
        flash("用户名或密码错误", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    """登出"""
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    """主仪表盘"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 统计数据
    c.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = c.fetchone()[0]

    c.execute("SELECT COALESCE(SUM(severity_high), 0) FROM scan_history")
    total_vulns = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM alerts WHERE is_read = 0")
    unread_alerts = c.fetchone()[0]

    c.execute("SELECT MAX(create_time) FROM scan_history")
    last_scan = c.fetchone()[0] or "暂无"

    # 最近扫描记录
    c.execute("SELECT scan_type, target, findings_count, severity_high, create_time FROM scan_history ORDER BY id DESC LIMIT 10")
    recent_scans = c.fetchall()

    # 最近告警
    c.execute("SELECT level, source, message, create_time FROM alerts ORDER BY id DESC LIMIT 10")
    recent_alerts = c.fetchall()

    # 趋势数据（最近20次扫描的 HIGH 数量）
    c.execute("SELECT severity_high, create_time FROM scan_history ORDER BY id DESC LIMIT 20")
    trend_data = list(reversed(c.fetchall()))

    conn.close()

    return render_template("index.html",
                         total_scans=total_scans,
                         total_vulns=total_vulns,
                         unread_alerts=unread_alerts,
                         last_scan=last_scan,
                         recent_scans=recent_scans,
                         recent_alerts=recent_alerts,
                         trend_data=json.dumps(trend_data))


@app.route("/scan")
@login_required
def scan_page():
    """扫描页面"""
    return render_template("scan.html")


# ===== API 接口 =====
@app.route("/api/scan/port", methods=["POST"])
@login_required
def api_scan_port():
    """端口扫描 API"""
    target = request.json.get("target", "127.0.0.1")
    socketio.emit("scan_progress", {"status": "scanning", "type": "port", "target": target})

    def _run():
        result = port_scanner.scan(target)
        scan_id = save_scan("port", target, result)
        socketio.emit("scan_result", {"type": "port", "id": scan_id, "result": result})
        if result["open_ports"] > 5:
            save_alert("WARNING", "端口扫描", f"{target} 开放了 {result['open_ports']} 个端口")
            socketio.emit("new_alert", {"level": "WARNING", "message": f"{target} 开放 {result['open_ports']} 个端口"})

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/scan/web", methods=["POST"])
@login_required
def api_scan_web():
    """Web 扫描 API"""
    target = request.json.get("target", "http://127.0.0.1")
    socketio.emit("scan_progress", {"status": "scanning", "type": "web", "target": target})

    def _run():
        result = web_scanner.scan(target)
        scan_id = save_scan("web", target, result)
        socketio.emit("scan_result", {"type": "web", "id": scan_id, "result": result})
        high_count = result.get("summary", {}).get("HIGH", 0)
        if high_count > 0:
            save_alert("CRITICAL", "Web扫描", f"{target} 发现 {high_count} 个高危漏洞")
            socketio.emit("new_alert", {"level": "CRITICAL", "message": f"{target} 发现 {high_count} 个高危漏洞"})

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/scan/logs", methods=["POST"])
@login_required
def api_scan_logs():
    """日志分析 API"""
    log_file = request.json.get("log_file", "/var/log/auth.log")

    def _run():
        try:
            with open(log_file, "r", errors="ignore") as f:
                content = f.read()
            result = log_analyzer.analyze(content)
            scan_id = save_scan("logs", log_file, result)
            socketio.emit("scan_result", {"type": "logs", "id": scan_id, "result": result})
            if result.get("brute_force_alerts"):
                save_alert("CRITICAL", "日志分析", f"检测到 {len(result['brute_force_alerts'])} 个暴力破解源")
                socketio.emit("new_alert", {"level": "CRITICAL", "message": f"检测到暴力破解"})
        except FileNotFoundError:
            socketio.emit("scan_result", {"type": "logs", "result": {"error": f"文件不存在: {log_file}"}})

    socketio.emit("scan_progress", {"status": "scanning", "type": "logs", "target": log_file})
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/history")
@login_required
def api_history():
    """获取扫描历史"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, scan_type, target, findings_count, severity_high, create_time FROM scan_history ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        "id": r[0], "type": r[1], "target": r[2],
        "findings": r[3], "high": r[4], "time": r[5]
    } for r in rows])


# ===== WebSocket 事件 =====
@socketio.on("connect")
def handle_connect():
    """客户端连接"""
    emit("connected", {"status": "ok", "time": datetime.now().strftime("%H:%M:%S")})


# ===== 启动 =====
if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("  Day7 进阶A: Web 安全仪表盘")
    print("  作者: YURM | 日期: 2026-05-23")
    print("=" * 60)
    print("  访问: http://localhost:5000")
    print("  账号: admin / admin123")
    print("=" * 60)
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
