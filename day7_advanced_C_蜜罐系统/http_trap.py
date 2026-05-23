#!/usr/bin/env python3
"""
HTTP 蜜罐模块 - 伪造管理后台页面，记录攻击者行为
作者: YURM | 日期: 2026-05-23

提供伪造的管理登录页面（WordPress/phpMyAdmin/Jenkins 风格）
记录所有 POST 登录尝试、请求头、访问路径
"""

import json
import logging
from datetime import datetime
from flask import Flask, request, Response

from database import log_http_attack

logger = logging.getLogger("http_trap")

# 伪造的 .env 文件内容
FAKE_ENV = """APP_NAME=ProductionApp
APP_ENV=production
APP_KEY=base64:Kx7vN2mP8qR3sT5uW6yZ0aB1cD4eF7gH9iJ2kL5mN8oP1qR=
APP_DEBUG=false
APP_URL=https://example.com

DB_CONNECTION=mysql
DB_HOST=192.168.1.101
DB_PORT=3306
DB_DATABASE=production
DB_USERNAME=webapp
DB_PASSWORD=W3bApp@2026!

REDIS_HOST=192.168.1.102
REDIS_PASSWORD=R3d!sS3cur3
REDIS_PORT=6379

MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=admin@example.com
MAIL_PASSWORD=Gm@ilAppP@ss2026

JWT_SECRET=xK9mN2pQ7rS4tU6vW8yZ0aB3cD5eF7gH1iJ4kL6mN9oP2qR=
"""

# 伪造的 .git/config
FAKE_GIT_CONFIG = """[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[remote "origin"]
    url = https://github.com/example/webapp.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
"""

# WordPress 登录页面模板
WP_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>Log In &lsaquo; WordPress</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #f1f1f1; }
        .login { width: 320px; margin: 7em auto; padding: 20px; background: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,.13); }
        .login h1 { text-align: center; }
        .login h1 a { background: url('') no-repeat center; width: 84px; height: 84px; display: block; margin: 0 auto 10px; text-indent: -9999px; }
        .login label { display: block; font-size: 14px; margin: 8px 0 4px; }
        .login input[type="text"], .login input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .login input[type="submit"] { width: 100%; background: #0073aa; color: #fff; border: none; padding: 10px; border-radius: 4px; cursor: pointer; font-size: 14px; margin-top: 12px; }
        .login input[type="submit"]:hover { background: #005a87; }
        .login .forgetmenot { margin: 10px 0; }
        #login_error { background: #fff; border-left: 4px solid #dc3232; padding: 12px; margin: 0 0 16px; }
    </style>
</head>
<body class="login">
    <div class="login">
        <h1><a href="/">WordPress</a></h1>
        <div id="login_error"><strong>错误</strong>: 用户名或密码不正确。<a href="#">忘记了密码？</a></div>
        <form method="post" action="/wp-login.php">
            <label for="user_login">用户名或电子邮件地址</label>
            <input type="text" name="log" id="user_login" autofocus>
            <label for="user_pass">密码</label>
            <input type="password" name="pwd" id="user_pass">
            <div class="forgetmenot">
                <label><input name="rememberme" type="checkbox"> 记住我的登录状态</label>
            </div>
            <input type="submit" name="wp-submit" value="登录">
        </form>
    </div>
</body>
</html>"""

# phpMyAdmin 登录页面
PHPMYADMIN_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>phpMyAdmin</title>
    <style>
        body { font-family: sans-serif; background: #f5f5f5; margin: 0; }
        .container { max-width: 400px; margin: 100px auto; background: #fff; padding: 30px; border: 1px solid #ccc; border-radius: 4px; }
        h2 { color: #444; text-align: center; }
        label { display: block; margin: 10px 0 5px; font-size: 13px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ccc; box-sizing: border-box; }
        input[type="submit"] { width: 100%; background: #6c7ae0; color: #fff; border: none; padding: 10px; cursor: pointer; margin-top: 15px; }
        .server { color: #888; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>phpMyAdmin</h2>
        <form method="post" action="/phpmyadmin/index.php">
            <label>用户名:</label>
            <input type="text" name="pma_username">
            <label>密码:</label>
            <input type="password" name="pma_password">
            <label>服务器: <span class="server">192.168.1.101:3306</span></label>
            <input type="submit" value="执行">
        </form>
    </div>
</body>
</html>"""


def create_http_honeypot(callback=None):
    """创建 HTTP 蜜罐 Flask 应用"""
    app = Flask(__name__)
    app.secret_key = "fake-honeypot-key"

    def log_request(attack_type="access"):
        """记录请求"""
        src_ip = request.remote_addr
        headers = dict(request.headers)
        log_http_attack(
            src_ip=src_ip,
            method=request.method,
            path=request.path,
            user_agent=request.headers.get("User-Agent", ""),
            post_data=str(request.form.to_dict()) if request.form else "",
            headers=json.dumps(headers)
        )
        if callback:
            callback("http_access", {
                "ip": src_ip, "method": request.method,
                "path": request.path, "type": attack_type
            })
        logger.info(f"[HTTP] {src_ip} {request.method} {request.path}")

    # WordPress 登录页面
    @app.route("/wp-login.php", methods=["GET", "POST"])
    @app.route("/wp-admin/", methods=["GET", "POST"])
    def wp_login():
        if request.method == "POST":
            log_request("login_attempt")
            logger.info(f"[HTTP] WordPress 登录尝试: {request.form.to_dict()}")
        return Response(WP_LOGIN_PAGE, content_type="text/html")

    # phpMyAdmin
    @app.route("/phpmyadmin/", methods=["GET", "POST"])
    @app.route("/phpmyadmin/index.php", methods=["GET", "POST"])
    def phpmyadmin():
        if request.method == "POST":
            log_request("login_attempt")
            logger.info(f"[HTTP] phpMyAdmin 登录尝试: {request.form.to_dict()}")
        return Response(PHPMYADMIN_PAGE, content_type="text/html")

    # .env 文件（诱饵）
    @app.route("/.env")
    def fake_env():
        log_request("sensitive_file")
        return Response(FAKE_ENV, content_type="text/plain")

    # .git/config（诱饵）
    @app.route("/.git/HEAD")
    def fake_git_head():
        log_request("sensitive_file")
        return Response("ref: refs/heads/main", content_type="text/plain")

    @app.route("/.git/config")
    def fake_git_config():
        log_request("sensitive_file")
        return Response(FAKE_GIT_CONFIG, content_type="text/plain")

    # admin 后台
    @app.route("/admin", methods=["GET", "POST"])
    @app.route("/admin/", methods=["GET", "POST"])
    def admin():
        if request.method == "POST":
            log_request("login_attempt")
        log_request("access")
        return Response(WP_LOGIN_PAGE.replace("WordPress", "Admin Panel"), content_type="text/html")

    # 通用路由（捕获所有请求）
    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
    def catch_all(path):
        log_request("access")
        return Response("<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The page was not found.</p></body></html>",
                       status=404, content_type="text/html")

    return app


def start_http_honeypot(port=8080, callback=None):
    """启动 HTTP 蜜罐"""
    app = create_http_honeypot(callback)
    logger.info(f"[HTTP] 蜜罐启动在端口 {port}")
    print(f"  [*] HTTP 蜜罐监听 0.0.0.0:{port}")
    print(f"  [*] 伪造页面: /wp-login.php, /phpmyadmin/, /admin/, /.env, /.git/")
    app.run(host="0.0.0.0", port=port, debug=False)
