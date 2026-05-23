#!/usr/bin/env python3
"""
威胁情报模块 - IP 地理定位 + 攻击者画像
作者: YURM | 日期: 2026-05-23
"""

import json
import logging
import sqlite3
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    requests = None

from database import DB_PATH

logger = logging.getLogger("threat_intel")

# 已知恶意 IP 段（示例）
KNOWN_BAD_RANGES = [
    "185.220.101", "185.220.102", "185.220.103",  # Tor exit nodes
    "45.155.205", "45.155.206",                     # 扫描器
    "198.51.100", "203.0.113",                      # 测试段
]


def lookup_ip(ip):
    """查询 IP 地理信息（使用免费 API）"""
    if not requests:
        return {"error": "requests 未安装"}

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,org,as", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "country": data.get("country", "未知"),
                "city": data.get("city", "未知"),
                "isp": data.get("isp", "未知"),
                "org": data.get("org", "未知"),
                "as": data.get("as", "未知"),
            }
    except Exception as e:
        logger.error(f"[威胁情报] IP查询失败: {ip} - {e}")

    return {"country": "未知", "city": "未知", "isp": "未知"}


def check_known_bad(ip):
    """检查 IP 是否在已知恶意范围内"""
    for bad_range in KNOWN_BAD_RANGES:
        if ip.startswith(bad_range):
            return True
    return False


def enrich_attacker_profiles():
    """批量丰富攻击者画像（添加地理位置信息）"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 获取没有地理信息的攻击者
    c.execute("SELECT ip FROM attacker_profiles WHERE country IS NULL OR country = ''")
    ips = [r[0] for r in c.fetchall()]

    for ip in ips:
        if ip in ("127.0.0.1", "::1"):
            continue

        geo = lookup_ip(ip)
        if "error" not in geo:
            c.execute(
                "UPDATE attacker_profiles SET country=?, city=? WHERE ip=?",
                (geo["country"], geo["city"], ip)
            )
            logger.info(f"[威胁情报] {ip} -> {geo['country']} {geo['city']}")

    conn.commit()
    conn.close()


def get_threat_summary():
    """获取威胁摘要"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT country, COUNT(*) as cnt FROM attacker_profiles WHERE country IS NOT NULL AND country != '未知' GROUP BY country ORDER BY cnt DESC LIMIT 10")
    countries = [{"country": r[0], "count": r[1]} for r in c.fetchall()]

    c.execute("SELECT ip, attack_count, severity, country FROM attacker_profiles WHERE severity IN ('HIGH', 'CRITICAL') ORDER BY attack_count DESC LIMIT 10")
    top_threats = [{"ip": r[0], "count": r[1], "severity": r[2], "country": r[3]} for r in c.fetchall()]

    conn.close()

    return {
        "top_countries": countries,
        "top_threats": top_threats
    }
