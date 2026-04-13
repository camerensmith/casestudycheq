# 🛡️ CHEQ Threat Mitigation Pipeline  
**Customer Success Engineering Prototype**

---

## ⚡ Local Setup (Avoid CORS)

The live GitHub Pages build fetches CSV data from an external endpoint. Running locally via the Vite dev server bypasses browser CORS restrictions and lets you work with the data directly.

```bash
npm install        # install dependencies
npm run dev        # start local dev server → http://localhost:5173
```

To build and preview the production bundle locally:

```bash
npm run build      # compile to /dist
npm run preview    # serve /dist → http://localhost:4173
```

> **Why this matters:** Browsers block cross-origin requests from `file://` or mismatched origins. The Vite dev/preview server proxies requests correctly, so the pipeline data loads without CORS errors.

---

## 1. What This Is (Modular System Overview)

This application is a **modular, configurable threat mitigation pipeline** that simulates how CHEQ protects Go-to-Market systems from invalid traffic (IVT), bot activity, and fraudulent interactions.

It is designed as a **composable system**, where each stage of the pipeline is isolated, configurable, and replaceable.

---

## 🧩 Modular Architecture

The system is built around **independent, replaceable modules**:

### 🔹 Ingestion Layer
- Fetches CSV data from endpoint  
- `parseCSV()` converts raw input into structured session objects  
- Handles:
  - type normalization (clicks, booleans)
  - timestamp standardization  

---

### 🔹 Detection Engine
- Config-driven (`DEFAULT_CONFIG`)  
- Multi-rule evaluation:
  - velocity spikes (`findVelocityIPs`)
  - impossible behavior (0s sessions + conversions)
  - bot user agents (`buildUARegex`)
  - geofencing (blocked countries)

---

### 🔹 Scoring System
- Weighted scoring model:

```
scores: { velocity: 45, impossible: 50, botUA: 45, geofence: 40 }
```

- Produces:
  - `risk_score (0–100+)`
  - classification:
    - Valid
    - Suspicious
    - Bot  

---

### 🔹 Mitigation Layer
- Threshold-based:

```
botThreshold: 80
```

- Outputs:
  - blocklisted IPs (local storage)
  - audit trail (`cheq_audit_trail_v1`)

---

### 🔹 Value Attribution Engine
- CPC-based loss modeling:

```
cpc: 5.0
```

- Calculates:
  - wasted spend
  - protected revenue
  - cost avoidance  

---

### 🔹 Visualization Layer
- React + Recharts dashboard  
- Surfaces:
  - traffic distribution
  - blocked threats
  - ROI impact
  - trend analysis  

---

## 🧠 Key Design Principle: Modularity

Each layer is **loosely coupled and replaceable**.

---

## 🤖 Agent-Friendly Codebase

This project is optimized for AI-assisted development and rapid ingestion by LLM agents.

- **[Quick Reference Guide (agents.md)](./agents.md)**: A structural map of the codebase designed for agents to quickly locate logic, state, and components.
- **Annotated Source**: `App.jsx` contains comprehensive comment blocks explaining the purpose and data flow of every major section.

---

## 2. How the Pipeline Is Used

Fetch → Parse → Analyze → Score → Mitigate → Quantify → Visualize  

---

## 🛠️ How to Run

```
npm install
npm run dev
```

Open: http://localhost:5173  

---

## 🚀 GitHub Pages (Deploys From `main`)

This repo is configured to auto-deploy from `main` via GitHub Actions:

- Workflow: `.github/workflows/pages.yml`
- Vite base path: `/casestudycheq/`

In GitHub repo settings:

1. Go to **Settings → Pages**
2. Set **Source** to **GitHub Actions**
3. Push to `main` to trigger deploy

Live URL:

`https://camerensmith.github.io/casestudycheq/`

---

## 3. Threat Definitions + Scoring Logic

Explainable rule-based detection using weighted signals.

This is actually a **really strong config surface**—you’ve basically built a mini policy engine. I’ll break each one down in **clean, interview-ready bullets** 👇

---

# ⚙️ Thresholds

## Cost Per Click (CPC) — `$5`

* Defines **financial impact per fraudulent interaction**
* Used in:

  * `Saved Spend = Fake Clicks × CPC`
* Higher CPC → higher urgency to block aggressively
* **Why it matters:**

  * Directly ties detection → business value
* **When to adjust:**

  * Campaign-specific pricing
  * Enterprise vs SMB accounts
  * Different traffic channels (search vs display)

---

## Bot Score Threshold — `80 pts`

* Minimum score required to **classify a session as a “Bot”**
* Anything ≥80 → triggers mitigation (blocking)
* **Why 80:**

  * High-confidence threshold (reduces false positives)
* **Tradeoff:**

  * Lower → more aggressive blocking
  * Higher → safer, but may miss bots
* **When to adjust:**

  * Lower if fraud is costly/high-volume
  * Raise if legitimate users are getting blocked

---

## Velocity Limit — `10 req`

* Max allowed requests per IP within the window
* Above this → triggers velocity rule
* **Why 10:**

  * Humans rarely exceed this naturally
* **What it detects:**

  * scraping
  * automation scripts
* **When to adjust:**

  * Increase for:

    * high-engagement apps
    * internal tools
  * Decrease for:

    * landing pages
    * paid ads (low tolerance for fraud)

---

## Velocity Window — `60s`

* Timeframe used to measure velocity
* Example:

  * 10 requests in 60s = threshold
* **Why 60s:**

  * Balances burst detection vs normal usage
* **When to adjust:**

  * Shorter (e.g. 10s) → detect aggressive bots
  * Longer (e.g. 5 min) → detect slow bots

---

# Score Weights (Risk Contribution)

These determine **how much each signal contributes to total risk_score**

---

## Velocity Score — `45 pts`

* Added when velocity rule is triggered
* **Meaning:**

  * Moderate-to-strong signal of bot activity
* **Why 45:**

  * Not enough alone to trigger blocking (needs combo)
* **When to adjust:**

  * Increase if velocity is highly correlated with fraud
  * Decrease if false positives occur

---

## Impossible Behavior Score — `50 pts`

* Triggered when:

  * `time_on_page = 0` AND `form_submitted = true`
* **Meaning:**

  * Extremely strong bot signal
* **Why highest weight:**

  * Humans cannot realistically do this
* **When to adjust:**

  * Rarely decreased (very reliable signal)

---

## Bot UA Score — `45 pts`

* Triggered when user agent matches known bot patterns
* Examples:

  * `bot`, `crawl`, `python-requests`, etc.
* **Why 45:**

  * Strong signal, but spoofable
* **When to adjust:**

  * Increase if scraping is common
  * Decrease if legitimate tools trigger false positives

---

## Geofence Score — `40 pts`

* Triggered when traffic comes from blocked countries
* **Meaning:**

  * Contextual risk, not definitive proof
* **Why lower weight:**

  * Location ≠ intent (avoid bias / false positives)
* **When to adjust:**

  * Increase for region-specific attacks
  * Decrease for global apps

---

# Blocked Countries (China, Russia)

* Hard-coded **risk policy layer**
* Automatically flags traffic from these regions
* **Why used:**

  * Known high-risk traffic sources (contextual)
* **Important:**

  * Should NOT be sole reason for blocking
* **When to adjust:**

  * Based on:

    * customer market
    * compliance
    * attack patterns

---

# Bot UA Patterns

Examples:

* `bot`, `crawl`, `spider`, `scrapy`
* `python-requests`, `curl`, `wget`
* `java`, `libwww`, `httpclient`

---

## What this does:

* Matches substrings in user-agent headers
* Flags likely **non-human traffic**

---

# 🔗 Data Source — `/api/cheq-csv`

* Endpoint for ingesting traffic data
* Abstracted so it can be swapped
* **Why this matters:**

  * Supports modular ingestion
* **Future:**

  * streaming (Kafka)
  * real-time APIs
  * warehouse integrations

---

## 4. Business Impact

- Direct savings via CPC protection  
- Breakeven ~3,200 fraudulent clicks/year (SMB)  
- Prevents wasted spend, bad data, and fraud  

---

## Strategic Value

- Protects revenue + data integrity  
- Reduces operational overhead  
- Enables expansion into compliance + accessibility (CHEQ + UserWay)

---

## Final Positioning

Modular pipeline translating threat detection into measurable business value.
