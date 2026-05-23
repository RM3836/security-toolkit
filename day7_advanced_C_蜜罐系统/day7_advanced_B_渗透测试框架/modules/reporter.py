# -*- coding: utf-8 -*-
"""
渗透测试框架 - 报告生成模块
作者: YURM
日期: 2026-05-23

功能:
  - Markdown 格式报告生成
  - JSON 结构化输出
  - 风险评分 (A-F 等级)
  - 修复建议
"""

import json
import os
import time
from datetime import datetime


class Colors:
    """终端颜色定义"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


# 严重程度权重
SEVERITY_WEIGHTS = {
    'Critical': 10,
    'High': 7,
    'Medium': 4,
    'Low': 2,
    'Info': 1,
}

# 风险等级定义
RISK_GRADES = [
    (80, 'F', '极高风险', Colors.RED + Colors.BOLD),
    (60, 'D', '高风险', Colors.RED),
    (40, 'C', '中等风险', Colors.YELLOW),
    (20, 'B', '低风险', Colors.CYAN),
    (0, 'A', '安全', Colors.GREEN),
]

# 通用修复建议
REMEDIATION_DB = {
    'SQL 注入': {
        'description': 'SQL 注入漏洞允许攻击者执行恶意 SQL 命令',
        'remediation': [
            '使用参数化查询 (Prepared Statements)',
            '实施输入验证和过滤',
            '使用 ORM 框架',
            '部署 Web 应用防火墙 (WAF)',
            '限制数据库用户权限',
            '定期进行代码审计',
        ],
    },
    'XSS': {
        'description': '跨站脚本攻击允许在用户浏览器中执行恶意脚本',
        'remediation': [
            '对所有输出进行 HTML 编码',
            '实施内容安全策略 (CSP)',
            '使用 HttpOnly 和 Secure Cookie 标志',
            '输入验证和过滤',
            '使用现代框架的自动转义功能',
        ],
    },
    '目录遍历': {
        'description': '目录遍历漏洞允许访问文件系统上的任意文件',
        'remediation': [
            '实施严格的输入验证',
            '使用 chroot 或容器隔离',
            '遵循最小权限原则',
            '避免在文件操作中使用用户输入',
            '使用白名单验证文件路径',
        ],
    },
    '命令注入': {
        'description': '命令注入漏洞允许在服务器上执行任意系统命令',
        'remediation': [
            '避免调用系统命令, 使用语言内置 API',
            '实施严格的输入白名单验证',
            '使用沙箱环境',
            '遵循最小权限原则',
        ],
    },
    '默认凭据': {
        'description': '使用默认凭据使攻击者容易获取系统访问权限',
        'remediation': [
            '修改所有默认密码',
            '实施强密码策略',
            '启用多因素认证 (MFA)',
            '定期轮换密码',
            '实施账户锁定策略',
        ],
    },
    'SSL': {
        'description': 'SSL/TLS 配置不当可能导致通信被窃听',
        'remediation': [
            '使用 TLS 1.2 或更高版本',
            '禁用弱密码套件',
            '使用有效的 CA 签名证书',
            '启用 HSTS',
            '定期更新证书',
        ],
    },
    '信息泄露': {
        'description': '信息泄露可能暴露系统架构和敏感数据',
        'remediation': [
            '移除调试信息和注释',
            '配置自定义错误页面',
            '移除不必要的 HTTP 头部',
            '限制目录列表',
            '保护敏感路径和文件',
        ],
    },
}


class ReporterModule:
    """
    报告生成模块

    将渗透测试各阶段的结果汇总生成结构化报告。
    """

    def __init__(self, target: str, scan_results: dict = None,
                 vuln_results: dict = None, exploit_results: dict = None,
                 recon_results: dict = None, output_dir: str = 'reports'):
        """
        初始化报告模块

        Args:
            target: 目标
            scan_results: 端口扫描结果
            vuln_results: 漏洞检测结果
            exploit_results: 利用演示结果
            recon_results: 信息收集结果
            output_dir: 输出目录
        """
        self.target = target
        self.scan_results = scan_results or {}
        self.vuln_results = vuln_results or {}
        self.exploit_results = exploit_results or {}
        self.recon_results = recon_results or {}
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    def _print_banner(self):
        """打印模块横幅"""
        banner = f"""
{Colors.GREEN}{'='*60}
  ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗
  ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
  ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║
  ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║
  ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║
  ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝
  报告生成模块 (Report Generator)
{'='*60}{Colors.END}"""
        print(banner)

    def calculate_risk_score(self) -> tuple:
        """
        计算风险评分

        根据发现的漏洞严重程度计算总分和等级。

        Returns:
            (分数, 等级, 描述) 元组
        """
        score = 0
        vulns = self.vuln_results.get('vulnerabilities', [])
        findings = self.exploit_results.get('findings', [])

        # 漏洞评分
        for vuln in vulns:
            severity = vuln.get('severity', 'Info')
            score += SEVERITY_WEIGHTS.get(severity, 1)

        # 利用发现评分
        for finding in findings:
            severity = finding.get('severity', 'Info')
            score += SEVERITY_WEIGHTS.get(severity, 1)

        # 确定等级
        grade = 'A'
        grade_desc = '安全'
        grade_color = Colors.GREEN
        for threshold, g, desc, color in RISK_GRADES:
            if score >= threshold:
                grade = g
                grade_desc = desc
                grade_color = color
                break

        return score, grade, grade_desc, grade_color

    def generate_markdown(self) -> str:
        """
        生成 Markdown 格式报告

        Returns:
            Markdown 报告内容
        """
        score, grade, grade_desc, _ = self.calculate_risk_score()

        md = []
        md.append(f'# 渗透测试报告')
        md.append(f'')
        md.append(f'**目标:** {self.target}')
        md.append(f'**日期:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        md.append(f'**作者:** YURM')
        md.append(f'**工具:** AutoPen 渗透测试框架')
        md.append(f'')
        md.append(f'---')
        md.append(f'')

        # 风险评估
        md.append(f'## 📊 风险评估')
        md.append(f'')
        md.append(f'| 指标 | 值 |')
        md.append(f'|------|-----|')
        md.append(f'| 风险等级 | **{grade}** - {grade_desc} |')
        md.append(f'| 风险评分 | {score} 分 |')
        vulns = self.vuln_results.get('vulnerabilities', [])
        findings = self.exploit_results.get('findings', [])
        md.append(f'| 漏洞数量 | {len(vulns)} |')
        md.append(f'| 安全发现 | {len(findings)} |')
        md.append(f'')

        # 漏洞统计
        if vulns:
            md.append(f'### 漏洞严重程度分布')
            md.append(f'')
            severity_count = {}
            for v in vulns:
                sev = v.get('severity', 'Info')
                severity_count[sev] = severity_count.get(sev, 0) + 1

            md.append(f'| 严重程度 | 数量 |')
            md.append(f'|----------|------|')
            for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                count = severity_count.get(sev, 0)
                if count > 0:
                    emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🔵', 'Info': '⚪'}.get(sev, '')
                    md.append(f'| {emoji} {sev} | {count} |')
            md.append(f'')

        # 扫描结果
        md.append(f'## 🔍 信息收集')
        md.append(f'')
        recon = self.recon_results
        if recon:
            dns = recon.get('dns_records', {})
            if dns.get('A'):
                md.append(f'### DNS 记录')
                md.append(f'')
                for rtype, records in dns.items():
                    if records:
                        for r in records:
                            md.append(f'- **{rtype}:** `{r}`')
                md.append(f'')

            subs = recon.get('subdomains', [])
            if subs:
                md.append(f'### 子域名')
                md.append(f'')
                md.append(f'| 子域名 | IP |')
                md.append(f'|--------|-----|')
                for s in subs:
                    md.append(f'| {s["subdomain"]} | {s["ip"]} |')
                md.append(f'')

            http_info = recon.get('http_info', {})
            if http_info:
                md.append(f'### Web 信息')
                md.append(f'')
                md.append(f'- **服务器:** {http_info.get("server", "未知")}')
                techs = http_info.get('technologies', [])
                if techs:
                    md.append(f'- **技术栈:** {", ".join(techs)}')
                md.append(f'')

        # 端口扫描
        open_ports = self.scan_results.get('open_ports', [])
        if open_ports:
            md.append(f'## 🔌 端口扫描')
            md.append(f'')
            md.append(f'| 端口 | 状态 | 服务 | Banner |')
            md.append(f'|------|------|------|--------|')
            for p in open_ports:
                banner = p.get('banner', '')[:40]
                md.append(f'| {p["port"]} | {p["state"]} | {p["service"]} | {banner} |')
            md.append(f'')

            os_guess = self.scan_results.get('os_guess', '未知')
            md.append(f'**操作系统推测:** {os_guess}')
            md.append(f'')

        # 漏洞详情
        if vulns:
            md.append(f'## ⚠️ 漏洞详情')
            md.append(f'')
            for i, vuln in enumerate(vulns, 1):
                md.append(f'### {i}. {vuln["type"]} [{vuln["severity"]}]')
                md.append(f'')
                md.append(f'**描述:** {vuln["description"]}')
                if vuln.get('evidence'):
                    md.append(f'')
                    md.append(f'**证据:**')
                    md.append(f'```')
                    md.append(f'{vuln["evidence"]}')
                    md.append(f'```')
                if vuln.get('remediation'):
                    md.append(f'')
                    md.append(f'**修复建议:** {vuln["remediation"]}')
                md.append(f'')

        # 安全发现
        if findings:
            md.append(f'## 🔐 安全发现')
            md.append(f'')
            for i, finding in enumerate(findings, 1):
                md.append(f'### {i}. {finding["category"]} [{finding["severity"]}]')
                md.append(f'')
                md.append(f'**描述:** {finding["description"]}')
                if finding.get('evidence'):
                    md.append(f'')
                    md.append(f'**证据:** `{finding["evidence"]}`')
                if finding.get('remediation'):
                    md.append(f'')
                    md.append(f'**修复建议:** {finding["remediation"]}')
                md.append(f'')

        # 修复建议总结
        md.append(f'## 🛡️ 修复建议总结')
        md.append(f'')
        all_types = set()
        for v in vulns:
            all_types.add(v.get('type', ''))
        for f_item in findings:
            all_types.add(f_item.get('category', ''))

        for vuln_type in all_types:
            for key, info in REMEDIATION_DB.items():
                if key.lower() in vuln_type.lower():
                    md.append(f'### {vuln_type}')
                    md.append(f'')
                    for rec in info['remediation']:
                        md.append(f'- {rec}')
                    md.append(f'')
                    break

        # 免责声明
        md.append(f'---')
        md.append(f'')
        md.append(f'## ⚖️ 免责声明')
        md.append(f'')
        md.append(f'本报告仅用于授权的安全测试目的。所有测试均在合法授权范围内进行。')
        md.append(f'未经授权对计算机系统进行渗透测试是违法行为。')
        md.append(f'')
        md.append(f'---')
        md.append(f'*报告由 AutoPen 渗透测试框架自动生成*')

        return '\n'.join(md)

    def generate_json(self) -> dict:
        """
        生成 JSON 结构化报告

        Returns:
            JSON 报告字典
        """
        score, grade, grade_desc, _ = self.calculate_risk_score()

        report = {
            'meta': {
                'target': self.target,
                'timestamp': datetime.now().isoformat(),
                'author': 'YURM',
                'tool': 'AutoPen 渗透测试框架',
                'version': '1.0.0',
            },
            'risk_assessment': {
                'score': score,
                'grade': grade,
                'grade_description': grade_desc,
            },
            'reconnaissance': self.recon_results,
            'port_scan': self.scan_results,
            'vulnerabilities': self.vuln_results.get('vulnerabilities', []),
            'exploitation_findings': self.exploit_results.get('findings', []),
            'summary': {
                'total_vulns': len(self.vuln_results.get('vulnerabilities', [])),
                'total_findings': len(self.exploit_results.get('findings', [])),
                'open_ports': len(self.scan_results.get('open_ports', [])),
                'subdomains': len(self.recon_results.get('subdomains', [])),
            },
            'disclaimer': '本报告仅用于授权的安全测试目的。',
        }

        return report

    def run(self) -> dict:
        """
        执行报告生成

        Returns:
            报告文件路径字典
        """
        self._print_banner()
        print(f"\n{Colors.BOLD}[*] 目标: {self.target}{Colors.END}")
        print(f"{Colors.BOLD}[*] 生成渗透测试报告...{Colors.END}")

        os.makedirs(self.output_dir, exist_ok=True)

        # 计算风险评分
        score, grade, grade_desc, grade_color = self.calculate_risk_score()

        # 生成 Markdown 报告
        md_content = self.generate_markdown()
        md_filename = f"pentest_report_{self.target}_{self.timestamp}.md"
        md_path = os.path.join(self.output_dir, md_filename)
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        print(f"  {Colors.GREEN}[+] Markdown 报告: {md_path}{Colors.END}")

        # 生成 JSON 报告
        json_content = self.generate_json()
        json_filename = f"pentest_report_{self.target}_{self.timestamp}.json"
        json_path = os.path.join(self.output_dir, json_filename)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_content, f, ensure_ascii=False, indent=2)
        print(f"  {Colors.GREEN}[+] JSON 报告: {json_path}{Colors.END}")

        # 打印风险评估
        print(f"\n{Colors.BOLD}{'='*50}")
        print(f"  渗透测试报告生成完成")
        print(f"{'='*50}{Colors.END}")
        print(f"  目标: {self.target}")
        print(f"  风险等级: {grade_color}{grade} - {grade_desc}{Colors.END}")
        print(f"  风险评分: {score} 分")
        print(f"  漏洞数量: {len(self.vuln_results.get('vulnerabilities', []))}")
        print(f"  安全发现: {len(self.exploit_results.get('findings', []))}")
        print(f"  开放端口: {len(self.scan_results.get('open_ports', []))}")
        print(f"{'='*50}{Colors.END}")

        return {
            'markdown': md_path,
            'json': json_path,
            'score': score,
            'grade': grade,
        }


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        module = ReporterModule(sys.argv[1])
        module.run()
    else:
        print("用法: python -m modules.reporter <目标域名>")
