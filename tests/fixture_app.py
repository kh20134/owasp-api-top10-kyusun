"""점검기가 기대하는 조치 후 응답과, 그에 못 미치는 응답."""

from __future__ import annotations

import logging
import threading

from flask import Flask, jsonify, redirect, request
from werkzeug.serving import WSGIRequestHandler, make_server

CSP = (
    "default-src 'self'; "
    "script-src 'self' 'nonce-fixture'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: blob: https://raw.githubusercontent.com; "
    "object-src 'none'; base-uri 'self'; form-action 'self'; "
    "frame-ancestors 'none'; upgrade-insecure-requests"
)


class QuietHandler(WSGIRequestHandler):
    server_version = "web"
    sys_version = ""

    def log_message(self, fmt: str, *args: object) -> None:
        return


def create_app(profile: str = "hardened", lock_after: int = 2) -> Flask:
    app = Flask(__name__)
    app.config["LOCK_AFTER"] = lock_after
    app.config["PROFILE"] = profile
    fails: dict[str, int] = {}
    app.extensions["login_posts"] = fails
    app.extensions["login_post_count"] = 0

    @app.after_request
    def harden(response):
        if app.config["PROFILE"] != "hardened":
            response.headers["Server"] = "Werkzeug/9.9.9"
            return response
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        if request.path.startswith("/admin"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["X-Robots-Tag"] = "noindex, nofollow"
        else:
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers.pop("Server", None)
        return response

    @app.get("/")
    def home():
        return "<!doctype html><title>home</title>"

    @app.get("/health")
    def health():
        if app.config["PROFILE"] != "hardened":
            return jsonify(status="ok", version="9.9.9")
        return jsonify(status="ok")

    @app.get("/admin/login")
    def login_get():
        body = (
            '<form method="post" action="/admin/login">'
            '<input type="hidden" name="csrf_token" value="tok">'
            '<input name="username"><input type="password" name="password">'
            "</form>"
        )
        response = app.response_class(body)
        if app.config["PROFILE"] == "hardened":
            response.set_cookie(
                "blog_session",
                "fixture",
                httponly=True,
                samesite="Lax",
                secure=request.is_secure,
                path="/",
            )
        else:
            response.set_cookie("session", "open", path="/")
        return response

    @app.post("/admin/login")
    def login_post():
        app.extensions["login_post_count"] += 1
        if request.form.get("csrf_token") != "tok":
            return redirect("/admin/login")
        ip = request.remote_addr or ""
        fails[ip] = fails.get(ip, 0) + 1
        if app.config["PROFILE"] == "hardened" and fails[ip] > app.config["LOCK_AFTER"]:
            response = app.response_class("locked", status=429)
            response.headers["Retry-After"] = "60"
            return response
        return redirect("/admin/login")

    def reject(path: str):
        if app.config["PROFILE"] != "hardened":
            return app.response_class("saved", status=200)
        return redirect("/admin/login?next=" + path)

    @app.post("/admin/logout")
    def logout():
        return reject("/admin/logout")

    @app.post("/admin/posts/<int:post_id>/delete")
    def delete_post(post_id: int):
        return reject(f"/admin/posts/{post_id}/delete")

    @app.post("/admin/categories/reorder")
    def reorder():
        return reject("/admin/categories/reorder")

    return app


def serve(app: Flask):
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    server = make_server("127.0.0.1", 0, app, threaded=True, request_handler=QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
