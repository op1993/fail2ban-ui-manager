#!/usr/bin/env python3
"""Local-only Fail2ban and Nginx discovery dashboard. No external dependencies."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs
from http.cookies import SimpleCookie
import json
import hashlib
import hmac
import time
import threading
import html
import ipaddress
import os
import re
import secrets
import subprocess

HOST = os.getenv("F2B_MANAGER_HOST", "0.0.0.0")
ALLOWED_NETWORKS = tuple(ipaddress.ip_network(cidr.strip()) for cidr in os.getenv("F2B_MANAGER_ALLOWED_NETWORKS", "127.0.0.0/8,192.168.0.0/24").split(",") if cidr.strip())
AUTH_FILE = Path("/etc/fail2ban-manager/auth.json")
SESSION_LIFETIME = 12 * 3600
LOGIN_ATTEMPTS = {}
LOGIN_LOCK = threading.Lock()
PORT = int(os.getenv("F2B_MANAGER_PORT", "8765"))
TOKEN = secrets.token_urlsafe(32)
JAIL_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
NGINX_DIR = Path("/etc/nginx/conf.d")

def auth_config():
    config = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    if not all(config.get(k) for k in ("username", "password_hash", "session_secret")):
        raise RuntimeError("Missing authentication configuration")
    return config

def password_matches(password, stored):
    try:
        algorithm, iterations, salt, expected = stored.split("$")
        if algorithm != "pbkdf2_sha256" or not 100000 <= int(iterations) <= 2000000:
            return False
        derived = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(derived, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False

def signed_session(username, secret):
    expires = int(time.time()) + SESSION_LIFETIME
    payload = f"{username}:{expires}"
    signature = hmac.new(bytes.fromhex(secret), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{signature}"

def valid_session(token, config):
    try:
        username, expiry, signature = token.rsplit(":", 2)
        if username != config["username"] or int(expiry) < time.time():
            return False
        payload = f"{username}:{expiry}"
        expected = hmac.new(bytes.fromhex(config["session_secret"]), payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)
    except (ValueError, KeyError):
        return False


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout

def jails():
    output = run("fail2ban-client", "status")
    match = re.search(r"Jail list:\s*(.*)", output)
    return [name.strip() for name in match.group(1).split(",") if name.strip()] if match else []

def jail_status(name):
    output = run("fail2ban-client", "status", name)
    def value(label):
        match = re.search(r"^.*" + re.escape(label) + r":\s*(.*)$", output, re.M)
        return match.group(1).strip() if match else ""
    return dict(name=name, failed=value("Currently failed"),
                banned=value("Currently banned"), ips=value("Banned IP list").split())

def sites():
    result = []
    for file in sorted(NGINX_DIR.glob("*.conf")):
        try:
            source = file.read_text(errors="replace")
        except OSError:
            continue
        names = re.findall(r"^\s*server_name\s+([^;]+);", source, re.M)
        if names:
            result.append((file.name, ", ".join(names),
                           bool(re.search(r"\$\w+_banned\b", source))))
    return result

class Handler(BaseHTTPRequestHandler):
    def allowed_client(self):
        try:
            address = ipaddress.ip_address(self.client_address[0])
            return any(address in network for network in ALLOWED_NETWORKS)
        except ValueError:
            return False

    def send(self, code, content, content_type="text/html; charset=utf-8"):
        data = content.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def authenticated(self):
        try:
            config = auth_config()
            cookies = SimpleCookie()
            cookies.load(self.headers.get("Cookie", ""))
            token = cookies["f2bm_session"].value if "f2bm_session" in cookies else ""
            return valid_session(token, config)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return False

    def login_page(self, error=""):
        style = "body{font:16px system-ui;background:#121826;color:#e7edf7;display:grid;place-items:center;min-height:90vh}form{background:#202c42;padding:32px;border-radius:12px;min-width:280px}input,button{display:block;box-sizing:border-box;width:100%;padding:11px;margin:12px 0;border-radius:6px}button{background:#547ce2;color:white;border:0;cursor:pointer}p{color:#ffaaa9}"
        page = ('<!doctype html><html lang="en"><meta charset="utf-8"><title>Sign in - Fail2ban Manager</title>'
                + f'<style>{style}</style><form method="post" action="/login"><h2>Fail2ban Manager</h2>'
                + (f'<p>{html.escape(error)}</p>' if error else '')
                + '<input name="username" autocomplete="username" placeholder="Username" required>'
                + '<input name="password" type="password" autocomplete="current-password" placeholder="Password" required>'
                + '<button type="submit">Sign in</button></form></html>')
        self.send(200, page)

    def read_form(self, max_length=2048):
        if self.headers.get("Content-Type", "").split(";")[0] != "application/x-www-form-urlencoded":
            raise ValueError("Unsupported media type")
        length = int(self.headers.get("Content-Length", "0"))
        if not 1 <= length <= max_length:
            raise ValueError("Invalid request length")
        return parse_qs(self.rfile.read(length).decode("utf-8"), strict_parsing=True)

    def redirect(self, cookie=None):
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if not self.allowed_client():
            return self.send(403, "Network not allowed", "text/plain")
        if self.path != "/":
            return self.send(404, "Not found", "text/plain")
        if not self.authenticated():
            return self.login_page()
        esc = html.escape
        try:
            records = [jail_status(jail) for jail in jails()]
            domains = sites()
            error = ""
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            records, domains, error = [], [], str(exc)
        rows = []
        for record in records:
            buttons = []
            for ip in record["ips"]:
                buttons.append(
                    '<form action="/unban" method="post" style="display:inline">'
                    + f'<input type="hidden" name="token" value="{TOKEN}">'
                    + f'<input type="hidden" name="jail" value="{esc(record["name"])}">'
                    + f'<input type="hidden" name="ip" value="{esc(ip)}">'
                    + f'<button>Unban {esc(ip)}</button></form>')
            rows.append(f'<tr><td>{esc(record["name"])}</td><td>{esc(record["failed"])}</td>'
                        + f'<td>{esc(record["banned"])}</td><td>{" ".join(buttons) or "—"}</td></tr>')
        domain_rows = [f'<tr><td>{esc(domain)}</td><td>{esc(file)}</td>'
                       + f'<td>{"Ban check found" if protected else "Not found"}</td></tr>'
                       for file, domain, protected in domains]
        style = "body{font:15px system-ui;background:#121826;color:#e7edf7;margin:0}main{max-width:1100px;margin:32px auto;padding:0 20px}table{width:100%;border-collapse:collapse;background:#202c42}td,th{text-align:left;padding:12px;border-bottom:1px solid #394760}button{background:#547ce2;border:0;color:white;padding:8px;border-radius:5px;cursor:pointer}p{color:#aebbd0}"
        page = ('<!doctype html><html lang="en"><meta charset="utf-8"><title>Fail2ban Manager</title>'
                + f'<style>{style}</style><main><form method="post" action="/logout" style="float:right"><input type="hidden" name="token" value="{TOKEN}"><button>Sign out</button></form><h1>Fail2ban Manager</h1>'
                + '<p>Local-only prototype. No configuration changes.</p>'
                + (f'<p>{esc(error)}</p>' if error else '')
                + '<h2>Jails</h2><table><tr><th>Jail</th><th>Failed</th><th>Banned</th><th>IP actions</th></tr>'
                + ''.join(rows) + '</table><h2>Nginx sites</h2>'
                + '<p>Ban check detection is heuristic and does not prove protection is active.</p>'
                + '<table><tr><th>Server name</th><th>File</th><th>Ban check</th></tr>'
                + ''.join(domain_rows) + '</table></main></html>')
        self.send(200, page)

    def do_POST(self):
        if not self.allowed_client():
            return self.send(403, "Network not allowed", "text/plain")
        if self.path == "/login":
            try:
                values = self.read_form()
                username = values.get("username", [""])[0]
                password = values.get("password", [""])[0]
                config = auth_config()
                # Global rate limit, including successful login attempts.
                with LOGIN_LOCK:
                    now = time.monotonic()
                    recent = [t for t in LOGIN_ATTEMPTS.get("global", []) if now - t < 60]
                    if len(recent) >= 10:
                        return self.send(429, "Too many attempts. Try again in one minute.", "text/plain")
                    recent.append(now)
                    LOGIN_ATTEMPTS["global"] = recent
                if not (hmac.compare_digest(username, config["username"]) and password_matches(password, config["password_hash"])):
                    return self.login_page("Invalid username or password")
                session = signed_session(username, config["session_secret"])
                return self.redirect("f2bm_session=" + session + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200")
            except (ValueError, KeyError, OSError, json.JSONDecodeError):
                return self.send(400, "Invalid login request", "text/plain")
        if not self.authenticated():
            return self.send(401, "Authentication required", "text/plain")
        if self.path == "/logout":
            try:
                values = self.read_form()
                if not secrets.compare_digest(values.get("token", [""])[0], TOKEN):
                    return self.send(403, "Forbidden", "text/plain")
            except ValueError:
                return self.send(400, "Bad request", "text/plain")
            return self.redirect("f2bm_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
        if self.path != "/unban":
            return self.send(404, "Not found", "text/plain")
        if self.headers.get("Content-Type", "").split(";")[0] != "application/x-www-form-urlencoded":
            return self.send(415, "Unsupported media type", "text/plain")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 2048:
                raise ValueError("Invalid request length")
            values = parse_qs(self.rfile.read(length).decode(), strict_parsing=True)
            def field(key):
                found = values[key]
                if len(found) != 1:
                    raise ValueError("Invalid field")
                return found[0]
            if not secrets.compare_digest(field("token"), TOKEN):
                return self.send(403, "Forbidden", "text/plain")
            jail, ip = field("jail"), field("ip")
            if not JAIL_PATTERN.fullmatch(jail) or jail not in jails():
                raise ValueError("Unknown jail")
            ipaddress.ip_address(ip)
            run("fail2ban-client", "set", jail, "unbanip", ip)
        except (ValueError, KeyError) as exc:
            return self.send(400, str(exc), "text/plain")
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            return self.send(500, str(exc), "text/plain")
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.end_headers()

if __name__ == "__main__":
    print(f"Listening on http://{HOST}:{PORT}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
