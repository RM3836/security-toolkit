# 🔐 网络安全工具集 — 7天安全挑战 + 进阶项目

**作者：** YURM (RM3836)
**时间：** 2026年5月
**学校：** 广州应用科技学院 · 网络工程

---

## 📁 项目总览

| 天数 | 项目 | 核心技术 | 状态 |
|------|------|----------|------|
| Day1 | 端口扫描器 | Python Socket, 多线程 | ✅ |
| Day2 | SSH批量管理系统 | Paramiko, 并发连接 | ✅ |
| Day3 | 网络流量分析 | Scapy, 数据包捕获 | ✅ |
| Day4 | Web漏洞扫描器 | Python, HTTP请求 | ✅ |
| Day5 | 日志分析系统 | 正则匹配, 异常检测 | ✅ |
| Day6 | 入侵检测系统(IDS) | 流量监控, 告警 | ✅ |
| Day7A | Web安全仪表盘 | Flask, SocketIO, Chart.js | ✅ |
| Day7B | AutoPen渗透测试框架 | 模块化架构, 5大模块 | ✅ |
| Day7C | 蜜罐+威胁情报系统 | Paramiko, Flask, WebSocket | ✅ |

---

## 🎯 重点项目：AutoPen 渗透测试框架

覆盖渗透测试全流程的自动化框架：

```
目标 → 信息收集 → 端口扫描 → 漏洞检测 → 安全利用 → 报告生成
```

**五大模块：**
- 📡 **Recon** — DNS查询、子域名枚举、敏感文件探测、安全头部检查
- 🔌 **Scanner** — TCP多线程扫描、服务Banner抓取、OS指纹识别
- 🐛 **Vuln** — SQL注入、XSS、目录遍历、命令注入、SSL/TLS检查
- 💀 **Exploiter** — 默认凭据测试、SSH安全检查、信息泄露收集
- 📋 **Reporter** — Markdown/JSON报告、A-F风险评分、修复建议

```bash
python3 pentest.py example.com --phase all
python3 pentest.py example.com --phase recon,scan,vuln
```

---

## 🍯 蜜罐 + 威胁情报系统

主动诱捕攻击者并分析行为：
- SSH蜜罐：伪造OpenSSH，记录密码和命令
- HTTP蜜罐：伪造WordPress/phpMyAdmin登录页
- 威胁情报：IP地理定位、攻击者画像
- 实时监控：WebSocket攻击流推送、攻击者排行榜

---

## 🛡️ Web安全仪表盘

实时安全监控面板（Flask + SocketIO）：
- 端口扫描 + Web漏洞扫描 + 日志分析
- WebSocket实时告警推送
- 暗色主题前端，Chart.js可视化

---

## 🛠️ 技术栈

**语言：** Python 3.10+
**网络：** Socket, Scapy, Paramiko
**Web：** Flask, Flask-SocketIO, Bootstrap 5
**安全：** Nmap, 渗透测试, 漏洞检测
**数据：** SQLite, JSON, WebSocket
**工具：** Docker, Git, Linux

---

## ⚠️ 免责声明

本项目仅供授权的安全测试和教育目的使用。未经授权对计算机系统进行渗透测试是违法行为。

---

## 📧 联系方式

- GitHub: [RM3836](https://github.com/RM3836)
- Email: steam3836@foxmail.com
