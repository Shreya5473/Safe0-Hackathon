# SafeO — ERP Risk Decision Engine
**Hackathon Category: Business, Finance, and Workforce ERP**

> SafeO is a real-time risk engine that lives *inside* Odoo — not in front of it.  
> Every CRM lead, financial note, and employee action is **scored before it is saved** — ALLOW, WARN, or BLOCK.

---

## Table of Contents
1. [What SafeO Does](#what-safeo-does)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Prerequisites](#prerequisites)
5. [Setup — Step by Step](#setup--step-by-step)
6. [Running Locally](#running-locally)
7. [Demo Flow](#demo-flow)
8. SafeO Brief
9. [Jira Integration](#jira-integration)


---

## What SafeO Does

| Scenario | Without SafeO | With SafeO |
|---|---|---|
| Malicious CRM lead submitted | Stored silently in DB | **Blocked before save** — scored, logged, Jira ticket created |
| Financial note with injection payload | Written to payment memo | **WARN flag** — saved with risk label, flagged for review |
| Employee submits anomalous HR action | No detection | **Behavioral signal** — pattern logged and surfaced on dashboard |
| Website signup with attack payload | Goes into Odoo contacts | **Blocked at form level** — never touches the database |

**Decision pipeline:** Input → Pattern scan → ML risk score → Policy check → ALLOW / WARN / BLOCK → ERP log + optional Jira ticket.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      ODOO (port 8069)                   │
│                                                         │
│  safeo_odoo/          ← Odoo addon (this repo)         │
│  ├── models/          ← Database models + business logic│
│  ├── controllers/     ← HTTP routes (/safeo/*)          │
│  ├── views/           ← XML menus, forms, dashboard     │
│  ├── security/        ← Access rights CSV + groups XML  │
│  └── static/          ← OWL dashboard JS/CSS/XML        │
│                                                         │
│  Calls ──────────────────────────────────────────────►  │
│                                                         │
│  safeo_backend/       ← FastAPI engine (port 8001)      │
│  ├── routers/         ← /erp/crm/lead, /erp/finance/…  │
│  ├── ml/              ← Tiered risk scorer + LLM guard  │
│  └── agents/          ← Behavior + input + output agents│
└─────────────────────────────────────────────────────────┘
```

All decisions are written to native Odoo models (`safeo.erp.decision`, `securec.log`, `securec.audit.log`) — queryable from any Odoo view or automation.

---

## Project Structure

```
SafeO-Hackathon/
│
├── safeo_odoo/                    ← Odoo 19 addon
│   ├── __init__.py
│   ├── __manifest__.py            ← Module metadata (name, depends, data files)
│   │
│   ├── models/                    ← Backend: database & business logic
│   │   ├── __init__.py
│   │   ├── crm_lead.py            ← Extends CRM lead with risk scoring
│   │   ├── erp_decision.py        ← Native ERP decision log model (safeo.erp.decision)
│   │   ├── ir_http_monitor.py     ← Global HTTP monitor (extends ir.http)
│   │   ├── securec_audit_log.py   ← ERP audit trail (securec.audit.log)
│   │   ├── securec_language.py    ← Arabic / Arabizi detection & normalization
│   │   ├── securec_log.py         ← WAF/risk log (securec.log) + Jira auto-create
│   │   ├── securec_policy.py      ← Regional compliance policies (UAE/EU/US/Global)
│   │   ├── securec_settings.py    ← Settings: API URL, thresholds, Jira config
│   │   └── website_public_layout.py ← Public user guard for website pages
│   │
│   ├── controllers/               ← Odoo HTTP controllers
│   │   ├── __init__.py
│   │   ├── main.py                ← /safeo/* API endpoints (metrics, logs, policies…)
│   │   ├── auth_audit.py          ← Login/logout audit hooks
│   │   └── website_waf.py        ← Website form & signup WAF protection
│   │
│   ├── views/                     ← Frontend: XML user interface
│   │   ├── menu.xml               ← SafeO ERP navigation bar
│   │   ├── securec_dashboard_views.xml  ← Client action for OWL dashboard
│   │   ├── securec_log_views.xml        ← Risk Engine Logs list/form
│   │   ├── securec_audit_views.xml      ← ERP Audit Trail list/form
│   │   ├── erp_decision_views.xml       ← ERP Decision Log list/form
│   │   ├── securec_policy_views.xml     ← Compliance Policies CRUD
│   │   ├── securec_settings_views.xml   ← Settings panel (inherits base settings)
│   │   ├── securec_attack_lab_views.xml ← Decision Lab template
│   │   └── crm_lead_views.xml           ← CRM lead form with risk banner
│   │
│   ├── security/
│   │   ├── ir.model.access.csv    ← Access rights for all models (MANDATORY)
│   │   └── securec_security.xml   ← SafeO User / SafeO Administrator groups
│   │
│   ├── data/
│   │   └── securec_data.xml       ← Default policy records (UAE, EU, US, Global)
│   │
│   └── static/src/
│       ├── css/securec.css        ← Dashboard styles (white/light theme)
│       ├── js/dashboard.js        ← OWL dashboard component
│       └── xml/securec_dashboard.xml  ← OWL template (safeo_odoo.Dashboard)
│
├── safeo_backend/                 ← FastAPI decision engine (Python)
│   ├── main.py                    ← FastAPI app entry point
│   ├── requirements.txt           ← Python dependencies
│   │
│   ├── routers/
│   │   ├── erp.py                 ← /erp/crm/lead, /erp/finance/action, …
│   │   ├── waf.py                 ← /waf/input, /waf/output
│   │   ├── simulate.py            ← /simulate/attack (batch simulation)
│   │   ├── metrics.py             ← /metrics
│   │   └── feedback.py            ← /feedback
│   │
│   ├── ml/
│   │   ├── risk_scorer.py         ← Heuristic + ML tiered risk scorer
│   │   ├── tiered_llm.py          ← LLM guard (only called when uncertain)
│   │   ├── keyword_detector.py    ← Fast pattern matching (SQLi, XSS, SSTI…)
│   │   ├── entropy.py             ← Entropy-based anomaly signal
│   │   └── llm_guard.py           ← LLM integration wrapper
│   │
│   ├── agents/
│   │   ├── behavior_agent.py      ← Per-user action baseline & anomaly
│   │   ├── input_agent.py         ← Pre-processing agent
│   │   └── output_agent.py        ← Post-scoring agent
│   │
│   └── models/
│       └── schemas.py             ← Pydantic request/response schemas
│
├── odoo.conf.example              ← Odoo config template (fill your DB creds)
└── README.md                      ← This file
```

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.10 – 3.13 | Odoo venv + FastAPI backend |
| Odoo | 19.0 | ERP framework |
| PostgreSQL | 14+ | Odoo database |
| Git | any | Version control |

---

## Setup — Step by Step

### 1 — Clone Odoo 19 (skip if you have it)
```bash
git clone https://github.com/odoo/odoo.git --branch 19.0 --depth 1 odoo
cd odoo
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2 — Place the SafeO addon
Copy the `safeo_odoo/` folder into your Odoo addons path:
```bash
# Example: if your addons path is odoo/addons/workshop/
cp -r safeo_odoo  odoo/addons/workshop/
# Then rename it back to securec_odoo (the module technical name Odoo expects):
mv odoo/addons/workshop/safeo_odoo odoo/addons/workshop/securec_odoo
```

> **Note:** The folder name on disk must be `securec_odoo` to match `__manifest__.py`. The user-facing branding is "SafeO" everywhere inside the module.

### 3 — Configure Odoo
Copy and edit the config:
```bash
cp odoo.conf.example odoo/odoo.conf
```
Edit `odoo.conf`:
```ini
[options]
db_host = localhost
db_port = 5432
db_user = YOUR_DB_USER
db_password =
addons_path = addons,odoo/addons,odoo/addons/workshop
db_name = safeo_db
list_db = False
```

Create the database:
```bash
createdb safeo_db
```

### 4 — Install the SafeO module
```bash
cd odoo
./venv/bin/python odoo-bin -c odoo.conf -d safeo_db -i securec_odoo --stop-after-init
```

### 5 — Set up the FastAPI backend
```bash
cd safeo_backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 6 — Start both servers
**Terminal 1 — Odoo:**
```bash
cd odoo
./venv/bin/python odoo-bin -c odoo.conf --http-port=8069
```

**Terminal 2 — FastAPI backend (from the repo root):**
```bash
# Run from the folder CONTAINING safeo_backend/ (not inside it)
cd ..   # go up one level from safeo_backend/
python3 -m venv .venv && source .venv/bin/activate
pip install -r safeo_backend/requirements.txt
python -m uvicorn safeo_backend.main:app --host 127.0.0.1 --port 8001
```

---

## Running Locally

| URL | Description |
|---|---|
| `http://127.0.0.1:8069/web/login` | Odoo login (default admin / admin) |
| `http://127.0.0.1:8069/odoo/safeo` | SafeO Business Risk Dashboard |
| `http://127.0.0.1:8001/docs` | FastAPI Swagger (all ERP endpoints) |
| `http://127.0.0.1:8001/health` | Backend health check |

After login, click **SafeO ERP** in the top navigation bar.

---

## Demo Flow

1. **Open Swagger** at `http://127.0.0.1:8001/docs` — show the `/erp/crm/lead`, `/erp/finance/action`, `/waf/input` endpoints exist.
2. **CRM lead with injection payload** — go to CRM → New Lead → paste `1 OR 1=1; DROP TABLE users; --` in the description → Save → see **BLOCK** toast.
3. **Decision Lab** — open SafeO ERP → Decision Lab → pick SQLi preset → Run Scan → see live risk score, explanation, and log rows.
4. **Dashboard** — go to Business Risk Dashboard → see blocked count, risk bars, "Latest Blocked Action", Jira escalation panel.
5. **Jira (optional)** — configure Settings → SafeO → Jira URL + token → a block event auto-opens a ticket.

---

## SafeO (Safe Odoo)

| Theme | SafeO coverage |
|---|---|
| **Business, Finance & Workforce ERP** *(primary)* | CRM leads scanned before save; financial notes scored; employee action behavior baseline |
| **Operational & Industrial ERP** | Procurement / purchase text covered by same pipeline; Global HTTP monitor for any installed app |
| **Public & Institutional ERP** | Website / portal forms protected; auth events auditable; public-sector-style compliance policies (UAE, EU, US) |

---

## Jira Integration

When a `securec.log` record is created with `risk_score >= 0.70`, SafeO automatically opens a Jira issue if credentials are configured:

**Settings → SafeO → Jira Integration:**
- **Jira Base URL** — e.g. `https://yourcompany.atlassian.net`
- **Jira User Email** — your Atlassian email
- **Jira API Token** — generate at `id.atlassian.com/manage-profile/security`
- **Jira Project Key** — e.g. `SEC`

The issue contains: module, risk score, decision, user, input preview, AI explanation.

The dashboard "From Risk → Action" card shows the ticket link live.

---

## Key Design Decisions

- **No core Odoo edits** — uses `_inherit` throughout; uninstall cleanly.
- **Fail-safe** — if the FastAPI backend is offline, every action is **allowed** (ERP stays functional, logs the offline event).
- **Tiered intelligence** — cheap heuristic rules run first; the LLM is only called when the score is uncertain (reduces cost).
- **Multilingual** — Arabic and Arabizi inputs are normalized before scanning.
- **`ir.model.access.csv` is complete** — all models have read/write/create/unlink rules for both user groups.

---

*Built by
team name- Pixel Coders
