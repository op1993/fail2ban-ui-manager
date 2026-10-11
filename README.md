# Fail2ban UI Manager

Lightweight web interface for an existing Fail2ban + Nginx installation.

## Stage 1
- Discover active Fail2ban jails and current banned IPs.
- Unban IPs via the UI.
- Discover Nginx site names from `/etc/nginx/conf.d/*.conf`.
- Indicate whether site configuration mentions a `*_banned` variable.

The Nginx detection is **heuristic**, not proof of effective blocking. This stage does not edit Nginx or Fail2ban configuration.

## Requirements
Python 3.9+, Fail2ban installed, Linux. No pip dependencies, Docker or database.

## Install on the nginx-ui LXC

```bash
git clone https://github.com/op1993/fail2ban-ui-manager.git /opt/fail2ban-manager
cd /opt/fail2ban-manager
python3 server.py
```

The service binds only to `127.0.0.1:8765`. From your workstation, establish an SSH tunnel to the container:

```bash
ssh -L 8765:127.0.0.1:8765 root@192.168.0.229
```

Then open http://127.0.0.1:8765.

**Security:** This is a local-only prototype without login/authentication. The form token is CSRF mitigation, not authentication. Never publish it through Nginx/Cloudflare or bind it to a public interface. It requires permissions to run `fail2ban-client` and unban addresses.

## Roadmap
- Authentication and privilege separation.
- Rule editing and `fail2ban-regex` dry-run.
- Per-site Nginx IP Map setup with preview, validation, backup and rollback.
- Safe systemd deployment.
