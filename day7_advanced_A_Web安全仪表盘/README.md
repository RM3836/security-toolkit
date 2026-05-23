# Day7 进阶A：Web 安全仪表盘

## 简介
基于 Flask + SocketIO 的实时安全监控面板，集成端口扫描、Web漏洞扫描、日志分析功能。

## 功能
- 📊 实时仪表盘（扫描统计、趋势图、告警列表）
- 🔌 一键端口扫描（TCP Connect，常见端口检测）
- 🌐 Web 漏洞扫描（信息收集 + 目录扫描 + XSS检测）
- 📊 日志分析（暴力破解检测、异常登录分析）
- 🔔 WebSocket 实时推送告警
- 📋 扫描历史持久化（SQLite）

## 运行
```bash
pip install -r requirements.txt
python3 app.py
# 访问 http://localhost:5000
# 账号: admin / admin123
```

## 技术栈
- Python 3.10+ / Flask 3.0 / Flask-SocketIO
- Bootstrap 5 (Dark Theme) / Chart.js 4
- SQLite / WebSocket

## 作者
YURM | 2026-05-23
