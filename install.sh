#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR=/opt/fail2ban-manager
SERVICE=fail2ban-manager
REPO=op1993/fail2ban-ui-manager
RAW_BASE=https://raw.githubusercontent.com/$REPO
SELF=/usr/bin/fail2ban-manager
ACTION=${1:-install}
INSTALLER_VERSION=2026-10-12.5
require_root() { if [[ ${EUID} -ne 0 ]]; then echo "Run as root" >&2; exit 1; fi; }
download() {
  local url="$1" destination="$2"
  curl --fail --location --silent --show-error --retry 3 --connect-timeout 10 --max-time 60 "$url" -o "$destination"
}
deploy() {
  require_root
  command -v python3 >/dev/null || { echo "Python 3 is required" >&2; exit 1; }
  command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
  command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }
  TMP_DIR=$(mktemp -d)
  trap 'if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then rm -rf -- "$TMP_DIR"; fi' EXIT
  download "https://api.github.com/repos/$REPO/commits/main?nocache=$(date +%s%N)" "$TMP_DIR/commit.json"
  COMMIT_SHA=$(python3 - "$TMP_DIR/commit.json" <<'PY'
import json, re, sys
with open(sys.argv[1], encoding="utf-8") as file:
    sha = json.load(file)["sha"]
if not re.fullmatch(r"[0-9a-f]{40}", sha):
    raise ValueError("Invalid commit SHA")
print(sha)
PY
)
  echo "Downloading GitHub commit: $COMMIT_SHA"
  download "$RAW_BASE/$COMMIT_SHA/server.py" "$TMP_DIR/server.py"
  # Check syntax without creating __pycache__ in the app directory.
  python3 - "$TMP_DIR/server.py" <<'PY'
import ast
import pathlib
import sys
ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
PY
  download "$RAW_BASE/$COMMIT_SHA/install.sh" "$TMP_DIR/install.sh"
  bash -n "$TMP_DIR/install.sh"
  mkdir -p /etc/fail2ban-manager
  if [[ ! -f /etc/fail2ban-manager/auth.json ]]; then
    [[ -t 0 ]] || { echo "Interactive terminal required for initial password setup" >&2; exit 1; }
    read -r -p "Admin username [admin]: " admin_name
    admin_name=${admin_name:-admin}
    [[ "$admin_name" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || exit 1
    read -r -s -p "Admin password (min 12 chars): " admin_pass
    echo
    [[ ${#admin_pass} -ge 12 ]] || { echo "Password too short" >&2; exit 1; }
    ADMIN_NAME="$admin_name" ADMIN_PASS="$admin_pass" python3 - <<'PY'
import hashlib, json, os, secrets
salt = secrets.token_bytes(16)
digest = hashlib.pbkdf2_hmac("sha256", os.environ["ADMIN_PASS"].encode(), salt, 350000)
data = {"username": os.environ["ADMIN_NAME"], "password_hash": "pbkdf2_sha256$350000$" + salt.hex() + "$" + digest.hex(), "session_secret": secrets.token_hex(32)}
fd = os.open("/etc/fail2ban-manager/auth.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, "w") as out:
    json.dump(data, out)
PY
    unset admin_pass
  fi
  mkdir -p "$APP_DIR"
  install -m 0644 "$TMP_DIR/server.py" "$APP_DIR/server.py"
  install -m 0755 "$TMP_DIR/install.sh" "$SELF"
  rm -f /usr/local/bin/fail2ban-manager
  cat >"/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=Local Fail2ban UI Manager
After=network.target fail2ban.service
Wants=fail2ban.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $APP_DIR/server.py
Restart=on-failure
RestartSec=3
User=root
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SERVICE.service" >/dev/null
  systemctl restart "$SERVICE.service"
  echo "Installed commit: $COMMIT_SHA"
  "$SELF" version
  echo "Installed/updated. UI: http://192.168.0.229:8765 (LAN only; login required)"
  systemctl --no-pager --full status "$SERVICE.service" || true
}
case "$ACTION" in
  install|update) deploy ;;
  version) echo "$INSTALLER_VERSION" ;;
  status) systemctl --no-pager --full status "$SERVICE.service" ;;
  restart) require_root; systemctl restart "$SERVICE.service"; systemctl --no-pager status "$SERVICE.service" ;;
  uninstall)
    require_root
    systemctl disable --now "$SERVICE.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE.service"
    systemctl daemon-reload
    rm -rf "$APP_DIR"
    rm -f "$SELF" /usr/local/bin/fail2ban-manager
    echo "Removed Fail2ban Manager (Nginx and Fail2ban untouched)."
    ;;
  *) echo "Usage: fail2ban-manager {install|update|status|restart|uninstall|version}" >&2; exit 2 ;;
esac
