#!/usr/bin/env python3
"""
蜜罐数据库模块 - 存储攻击记录和攻击者画像
作者: YURM | 日期: 2026-05-23
"""

import sqlite3
import json
from datetime import datetime

DB_PATH = "honeypot.db"


def init_db():
    """初始化数据库表"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # SSH 攻击记录
    c.execute("""CREATE TABLE IF NOT EXISTS ssh_attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT NOT NULL,
        src_port INTEGER,
        username TEXT,
        password TEXT,
        command TEXT,
        session_id TEXT,
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

    # HTTP 攻击记录
    c.execute("""CREATE TABLE IF NOT EXISTS http_attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT NOT NULL,
        method TEXT,
        path TEXT,
        user_agent TEXT,
        post_data TEXT,
        headers_json TEXT,
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

    # 攻击者画像
    c.execute("""CREATE TABLE IF NOT EXISTS attacker_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        country TEXT,
        city TEXT,
        org TEXT,
        attack_count INTEGER DEFAULT 0,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        attack_types TEXT,
        severity TEXT DEFAULT 'LOW'
    )""")

    conn.commit()
    conn.close()


def log_ssh_attack(src_ip, src_port, username, password, command="", session_id=""):
    """记录 SSH 攻击"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO ssh_attacks (src_ip, src_port, username, password, command, session_id) VALUES (?,?,?,?,?,?)",
        (src_ip, src_port, username, password, command, session_id)
    )
    conn.commit()
    conn.close()
    _update_attacker_profile(src_ip, "SSH")


def log_http_attack(src_ip, method, path, user_agent="", post_data="", headers=""):
    """记录 HTTP 攻击"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO http_attacks (src_ip, method, path, user_agent, post_data, headers_json) VALUES (?,?,?,?,?,?)",
        (src_ip, method, path, user_agent, post_data, headers)
    )
    conn.commit()
    conn.close()
    _update_attacker_profile(src_ip, "HTTP")


def _update_attacker_profile(ip, attack_type):
    """更新攻击者画像"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute("SELECT id, attack_count, attack_types FROM attacker_profiles WHERE ip = ?", (ip,))
    row = c.fetchone()

    if row:
        types = set(json.loads(row[2]) if row[2] else [])
        types.add(attack_type)
        count = row[1] + 1
        severity = "CRITICAL" if count > 20 else "HIGH" if count > 10 else "MEDIUM" if count > 5 else "LOW"
        c.execute(
            "UPDATE attacker_profiles SET attack_count=?, attack_types=?, last_seen=?, severity=? WHERE id=?",
            (count, json.dumps(list(types)), now, severity, row[0])
        )
    else:
        c.execute(
            "INSERT INTO attacker_profiles (ip, attack_count, attack_types, first_seen, last_seen, severity) VALUES (?,?,?,?,?,?)",
            (ip, 1, json.dumps([attack_type]), now, now, "LOW")
        )

    conn.commit()
    conn.close()


def get_stats():
    """获取统计数据"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM ssh_attacks")
    ssh_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM http_attacks")
    http_count = c.fetchone()[0]

    c.execute("SELECT COUNT(DISTINCT ip) FROM attacker_profiles")
    unique_ips = c.fetchone()[0]

    c.execute("SELECT ip, attack_count, severity, country, attack_types, last_seen FROM attacker_profiles ORDER BY attack_count DESC LIMIT 20")
    attackers = [{
        "ip": r[0], "count": r[1], "severity": r[2],
        "country": r[3] or "未知", "types": json.loads(r[4]) if r[4] else [],
        "last_seen": r[5]
    } for r in c.fetchall()]

    c.execute("SELECT src_ip, username, password, create_time FROM ssh_attacks ORDER BY id DESC LIMIT 20")
    recent_ssh = [{"ip": r[0], "user": r[1], "pass": r[2], "time": r[3]} for r in c.fetchall()]

    c.execute("SELECT src_ip, method, path, post_data, create_time FROM http_attacks ORDER BY id DESC LIMIT 20")
    recent_http = [{"ip": r[0], "method": r[1], "path": r[2], "data": r[3], "time": r[4]} for r in c.fetchall()]

    conn.close()

    return {
        "ssh_attacks": ssh_count,
        "http_attacks": http_count,
        "unique_attackers": unique_ips,
        "attackers": attackers,
        "recent_ssh": recent_ssh,
        "recent_http": recent_http
    }
