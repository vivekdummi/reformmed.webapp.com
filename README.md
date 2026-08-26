# REFORMMED Monitor — Custom Flask Dashboard

Replaces Grafana with a fully custom Flask web app integrated directly into the existing PostgreSQL + FastAPI stack.

## Architecture

```
                  ┌──────────────────────────────────────┐
                  │         Docker Compose Stack         │
                  │                                      │
  Agents ──────►  │  :8000  FastAPI (main.py)            │
  (metrics push)  │         ↕ PostgreSQL                 │
                  │                                      │
  Browser ──────► │  :5000  Flask Webapp (app.py)        │
                  │         • Login / session auth       │
                  │         • Home overview              │
                  │         • Server list + details      │
                  │         • User management (admin)    │
                  │         • Alert config + log         │
                  │                                      │
                  │  Checker (offline_checker.py)        │
                  │         • Reads alert config from DB │
                  │         • Sends emails               │
                  └──────────────────────────────────────┘
```

## Directory layout

```
webapp/
├── app.py                  ← Flask factory + entry point
├── db.py                   ← psycopg2 helpers + DB init
├── models.py               ← User model (Flask-Login)
├── alert_sender.py         ← Shared email helper
├── offline_checker.py      ← Daemon (reads alert config from DB)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml      ← Full stack (replaces server/docker-compose.yml)
├── .env.example
├── blueprints/
│   ├── auth.py             ← /login, /logout
│   ├── home.py             ← / (overview)
│   ├── servers.py          ← /servers/, /servers/<name>
│   ├── users.py            ← /users/ (admin only)
│   ├── alerts.py           ← /alerts/
│   └── api.py              ← /api/* (AJAX)
└── templates/
    ├── base.html           ← Sidebar + navbar layout
    ├── login.html
    ├── home.html
    ├── servers.html
    ├── server_detail.html  ← Live charts + metrics
    ├── users.html
    ├── user_edit.html
    └── alerts.html
```

## Quick Start

1. Copy `server/main.py` stays where it is (agents still POST to :8000)
2. Place the `webapp/` folder alongside `server/`
3. Copy `.env.example` → `.env` and fill in values
4. Run:

```bash
cp webapp/.env.example .env
# edit .env
docker compose -f webapp/docker-compose.yml --env-file .env up -d
```

5. Open `http://YOUR_IP:5000`
6. Login: **admin / admin123** → change password immediately

## Roles

| Role  | Permissions |
|-------|-------------|
| Admin | Everything: all servers, users, alert config |
| User  | View-only on selected servers + alerts log |

Admins create users and assign which servers each user can see via the Users page.

## Alert Configuration

All alert thresholds (CPU %, RAM %, disk %, temp °C) and recipient emails are managed
from the **Alerts** page in the webapp — no need to edit `.env` or restart containers.

Changes take effect within one check cycle (default: 15 seconds).

## Keeping the existing checker

The `offline_checker.py` in this webapp replaces the original one. Key differences:
- Reads all thresholds + recipients from the `alert_config` DB table (set via webapp)
- Logs every alert to `alert_log` table (visible in webapp)
- Falls back to `ALERT_TO` env var if no emails configured in DB
