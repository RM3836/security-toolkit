# AutoPen - 自动化渗透测试框架

**作者:** YURM  
**日期:** 2026-05-23  
**版本:** 1.0.0

## 📋 简介

AutoPen 是一个专业的自动化渗透测试框架, 用于对目标系统进行全面的安全评估。框架集成了信息收集、端口扫描、漏洞检测、安全利用和报告生成五大模块, 能够自动化完成渗透测试的各个阶段。

### ⚠️ 免责声明

**本工具仅供授权的安全测试和教育目的使用。**  
未经授权对计算机系统进行渗透测试是违法行为, 可能导致严重的法律后果。使用本工具前, 请确保您已获得目标系统所有者的明确书面授权。

## 🚀 功能特性

### 1. 信息收集模块 (Recon)
- DNS 记录查询 (A, MX, NS, TXT, CNAME)
- HTTP 头部和技术栈分析
- 子域名枚举 (多线程 DNS 爆破)
- 敏感文件探测 (robots.txt, sitemap.xml, .env 等)
- 安全头部检查

### 2. 端口扫描模块 (Scanner)
- TCP 连接扫描 (多线程, Top 1000 端口)
- 服务 Banner 抓取
- OS 指纹识别 (基于 TTL 和端口特征)
- 常见服务识别

### 3. 漏洞检测模块 (Vuln)
- SQL 注入检测 (错误型、时间型)
- XSS 反射检测
- 目录遍历检测
- 命令注入检测
- SSL/TLS 安全检查

### 4. 安全利用模块 (Exploiter)
- 默认凭据测试
- SSH 安全检查
- 目录列表检测
- 信息泄露收集
- **所有操作均为只读和伦理性质**

### 5. 报告生成模块 (Reporter)
- Markdown 格式报告
- JSON 结构化输出
- 风险评分 (A-F 等级)
- 详细修复建议

## 📦 安装

### 系统要求

- Python 3.8+
- Linux / macOS / Windows (WSL)

### 安装步骤

```bash
# 克隆项目
cd /path/to/project

# 安装依赖
pip install -r requirements.txt
```

## 🎯 使用方法

### 基本用法

```bash
# 执行完整渗透测试 (所有阶段)
python3 pentest.py example.com --phase all

# 仅执行信息收集
python3 pentest.py example.com --phase recon

# 仅执行端口扫描
python3 pentest.py example.com --phase scan

# 仅执行漏洞检测
python3 pentest.py example.com --phase vuln

# 仅执行安全利用
python3 pentest.py example.com --phase exploit

# 仅生成报告
python3 pentest.py example.com --phase report

# 执行多个阶段
python3 pentest.py example.com --phase recon,scan,vuln
```

### 高级选项

```bash
# 指定输出目录
python3 pentest.py example.com --phase all --output ./my_reports

# 指定扫描线程数
python3 pentest.py example.com --phase scan --threads 200

# 指定自定义字典
python3 pentest.py example.com --phase recon --wordlist ./my_wordlist.txt
```

## 📁 项目结构

```
day7_advanced_B_渗透测试框架/
├── pentest.py              # 主入口文件
├── modules/
│   ├── __init__.py         # 模块初始化
│   ├── recon.py            # 信息收集模块
│   ├── scanner.py          # 端口扫描模块
│   ├── vuln.py             # 漏洞检测模块
│   ├── exploiter.py        # 安全利用模块
│   └── reporter.py         # 报告生成模块
├── wordlists/
│   ├── common_users.txt    # 常见用户名字典
│   ├── common_passwords.txt # 常见密码字典
│   └── subdomains.txt      # 子域名字典
├── reports/                # 报告输出目录
├── requirements.txt        # 依赖列表
└── README.md              # 本文件
```

## 📊 输出示例

### 终端输出

```
============================================================
  AutoPen 渗透测试框架 v1.0.0
  作者: YURM
============================================================

[*] 目标: example.com
[*] 阶段: recon, scan, vuln, exploit, report

[*] 开始信息收集...
[+] A 记录: 93.184.216.34
[+] 服务器: ECS
[+] 检测到技术: Nginx
...

[*] 开始端口扫描...
[+] 80/tcp 开放  HTTP
[+] 443/tcp 开放  HTTPS
...

[*] 开始漏洞检测...
[!] [High] SQL 注入 (错误型): 参数 id 存在 SQL 注入
...

[*] 生成报告...
[+] Markdown 报告: reports/pentest_report_example.com_20260523.md
[+] JSON 报告: reports/pentest_report_example.com_20260523.json

============================================================
  风险等级: D - 高风险
  风险评分: 45 分
============================================================
```

### Markdown 报告

报告包含以下章节:
- 风险评估 (等级、评分、统计)
- 信息收集结果
- 端口扫描结果
- 漏洞详情 (按严重程度分类)
- 安全发现
- 修复建议总结
- 免责声明

## 🔧 自定义扩展

### 添加新的漏洞检测

在 `modules/vuln.py` 中添加新的检测方法:

```python
def my_custom_check(self):
    """自定义漏洞检测"""
    print(f"\n[*] 执行自定义检测...")
    # 实现检测逻辑
    self._add_vuln(
        '自定义漏洞', 'Medium',
        '漏洞描述',
        '证据信息',
        '修复建议'
    )
```

### 添加新的子域名字典

编辑 `wordlists/subdomains.txt`, 每行一个子域名前缀。

## ⚡ 性能优化

- 端口扫描默认使用 100 个线程, 可通过 `--threads` 参数调整
- 子域名枚举默认使用 20 个线程
- 所有网络请求均设置了超时时间, 避免长时间等待

## 🐛 常见问题

### Q: 为什么某些检测结果不准确?
A: 自动化工具可能存在误报, 建议人工验证关键发现。

### Q: 如何提高扫描速度?
A: 可以增加线程数 (`--threads`), 或仅执行特定阶段 (`--phase`)。

### Q: 报告在哪里?
A: 默认在 `reports/` 目录下, 可通过 `--output` 参数自定义。

## 📝 更新日志

### v1.0.0 (2026-05-23)
- 初始版本发布
- 实现五大核心模块
- 支持 Markdown 和 JSON 报告
- 支持多线程扫描

## 📄 许可证

本项目仅供教育和授权安全测试使用。

## 👤 作者

**YURM**  
*安全研究员*

---

*本工具由 AutoPen 渗透测试框架自动生成*
