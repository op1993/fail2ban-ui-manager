#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR=/opt/fail2ban-manager
SERVICE=fail2ban-manager
RAW=https://raw.githubusercontent.com/op1993/fail2ban-ui-manager/main
SELF=/usr/local/bin/fail2ban-manager
ACTION=${1:-install}
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
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  download "$RAW/server.py" "$tmp/server.py"
  # Check syntax without creating __pycache__ in the app directory.
  python3 - "$tmp/server.py" <<'PY'
import ast
import pathlib
import sys
ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
PY
  download "$RAW/install.sh" "$tmp/install.sh"
  mkdir -p "$APP_DIR"
  install -m 0644 "$tmp/server.py" "$APP_DIR/server.py"
  install -m 0755 "$tmp/install.sh" "$SELF"
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
  echo "Installed/updated. UI: http://127.0.0.1:8765 (SSH tunnel required)"
  systemctl --no-pager --full status "$SERVICE.service" || true
}
case "$ACTION" in
  install|update) deploy ;;
  status) systemctl --no-pager --full status "$SERVICE.service" ;;
  restart) require_root; systemctl restart "$SERVICE.service"; systemctl --no-pager status "$SERVICE.service" ;;
  uninstall)
    require_root
    systemctl disable --now "$SERVICE.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE.service"
    systemctl daemon-reload
    rm -rf "$APP_DIR"
    rm -f "$SELF"
    echo "Removed Fail2ban Manager (Nginx and Fail2ban untouched)."
    ;;
  *) echo "Usage: fail2ban-manager {install|update|status|restart|uninstall}" >&2; exit 2 ;;
esac
