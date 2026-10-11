#!/usr/bin/env python3
"""Local-only Fail2ban and Nginx discovery dashboard. No external dependencies."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs
import html
import ipaddress
import os
import re
import secrets
import subprocess

HOST = "127.0.0.1"
PORT = int(os.getenv("F2B_MANAGER_PORT", "8765"))
TOKEN = secrets.token_urlsafe(32)
JAIL_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
NGINX_DIR = Path("/etc/nginx/conf.d")

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

    def do_GET(self):
        if self.path != "/":
            return self.send(404, "Not found", "text/plain")
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
                + f'<style>{style}</style><main><h1>Fail2ban Manager</h1>'
                + '<p>Local-only prototype. No configuration changes.</p>'
                + (f'<p>{esc(error)}</p>' if error else '')
                + '<h2>Jails</h2><table><tr><th>Jail</th><th>Failed</th><th>Banned</th><th>IP actions</th></tr>'
                + ''.join(rows) + '</table><h2>Nginx sites</h2>'
                + '<p>Ban check detection is heuristic and does not prove protection is active.</p>'
                + '<table><tr><th>Server name</th><th>File</th><th>Ban check</th></tr>'
                + ''.join(domain_rows) + '</table></main></html>')
        self.send(200, page)

    def do_POST(self):
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
