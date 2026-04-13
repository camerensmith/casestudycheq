## 0. Objective

This document outlines the **reverse-engineered product requirements and architectural decisions** behind the Automated Threat Mitigation Pipeline.

The goal is to ensure the solution:

* Fully satisfies assignment requirements 
* Demonstrates **modularity and extensibility**
* Aligns with **real-world Go-To-Market Security (GTMSec)** systems
* Maximizes **customer-facing value and ROI communication**

---

## 1. Problem Statement

TechCorp is experiencing:

* Budget loss due to **invalid traffic (IVT)**
* Data corruption from **bot interactions**
* Lack of **automated mitigation**
* No visibility into **financial impact**

👉 The system must not only detect threats, but:

> **automatically act and clearly quantify value**

---

## 2. Success Criteria

### Functional Requirements

| Requirement                 | Status |
| --------------------------- | ------ |
| Ingest traffic data         | ✅      |
| Detect malicious sessions   | ✅      |
| Assign risk score + verdict | ✅      |
| Automate mitigation         | ✅      |
| Track blocked IPs           | ✅      |
| Calculate financial impact  | ✅      |
| Visualize value             | ✅      |

---

### Non-Functional Requirements

| Requirement    | Approach                          |
| -------------- | --------------------------------- |
| Modularity     | Decoupled pipeline layers         |
| Extensibility  | Config-driven rules + scoring     |
| Observability  | Audit trail + dashboard           |
| Automation     | Stateless pipeline execution      |
| Explainability | Rule-based scoring (no black box) |

---

## 3. System Architecture

### 🔄 High-Level Flow

```
Ingestion → Normalization → Detection → Scoring → Mitigation → Value Attribution → Visualization
```

---

### 🧩 Architectural Principles

#### 1. Modularity First

Each system component is independently replaceable:

* Detection → can evolve to ML
* Ingestion → can evolve to streaming
* Mitigation → can integrate with real WAF/CDN

---

#### 2. Config-Driven Behavior

All detection and scoring logic lives in a central config:

* thresholds (`velocityLimit`, `botThreshold`)
* weights (`scores`)
* policies (`blockedCountries`)

👉 Enables:

* fast tuning
* customer-specific policies
* A/B experimentation

---

#### 3. Stateless Execution

* Pipeline can run:

  * hourly
  * batch-based
  * serverless

👉 Minimizes infrastructure complexity

---

## 4. Detection & Scoring Design

### 🎯 Why Rule-Based?

Chosen over ML because:

* deterministic
* explainable to customers
* fast to implement
* aligns with CSE workflows

---

### 🚨 Detection Signals

| Signal              | Reasoning                         |
| ------------------- | --------------------------------- |
| Velocity            | Bots operate at unnatural speeds  |
| Impossible Behavior | Indicates automation/script abuse |
| Bot UA              | Known crawler patterns            |
| Geofencing          | High-risk regions                 |

---

### ⚖️ Scoring Strategy

* Additive weighted model
* Score accumulation reflects **confidence of maliciousness**

```
risk_score = Σ(signal weights)
```

---

### 🎯 Classification

| Score | Meaning    |
| ----- | ---------- |
| <50   | Valid      |
| 50–79 | Suspicious |
| ≥80   | Bot        |

---

### 🔧 Why This Matters

* Transparent to customer
* Tunable per use case
* Easy to justify in ROI conversations

---

## 5. Mitigation Strategy

### 🛑 Decision

* Only block **high-confidence threats (≥80)**

### Why?

* avoids false positives
* aligns with enterprise risk tolerance
* builds trust in automation

---

### 🔁 Simulation Design

Instead of real firewall:

* store in `blocked_ips.json`
* maintain audit log

👉 Mirrors production behavior without infra complexity

---

## 6. Value Attribution Model

### 💰 Formula

```
Saved Spend = Fraudulent Clicks × CPC
```

---

### 🎯 Why CPC?

* Simple
* Universally understood by GTM teams
* Easy to communicate

---

### ⚖️ Tradeoffs

| Approach             | Decision                    |
| -------------------- | --------------------------- |
| CPC model            | ✅ simple, explainable       |
| LTV model            | ❌ too complex for prototype |
| Attribution modeling | ❌ overkill                  |

---

## 7. Dashboard Design (Proof of Value)

### 🧠 Goal

Not just analytics → **Customer storytelling**

---

### 📊 Metrics Selected

| Metric                | Why             |
| --------------------- | --------------- |
| Total Traffic         | Context         |
| Money Saved           | Primary KPI     |
| Blocked IPs           | Trust signal    |
| Conversion Protection | Business impact |

---

### 📈 Visuals

* Valid vs Malicious chart → clarity
* Recent threats → transparency

---

## 8. Cost vs Benefit Framing

### 💸 CHEQ Pricing Context

* SMB: ~$16K/year
* Enterprise: ~$61K/year

---

### 📉 Breakeven

```
~3,200 fraudulent clicks/year (SMB)
```

---

### ⚠️ Opportunity Cost

Without solution:

* wasted spend compounds
* bad data drives decisions
* sales teams chase fake leads

---

### 🧠 Non-Quantifiable Value

* Work stoppage
* Data pollution
* Security exposure
* Compliance risk

👉 Often exceeds direct CPC loss

---

## 9. Key Architectural Tradeoffs

| Decision                | Tradeoff                 |
| ----------------------- | ------------------------ |
| Rule-based detection    | Less adaptive than ML    |
| Local storage           | Not scalable, but simple |
| Batch pipeline          | Not real-time            |
| Frontend-only dashboard | No persistence layer     |

---

## 10. Future Enhancements

### 🚀 Technical

* Real-time streaming ingestion
* ML anomaly detection
* Redis/IP cache
* API-driven mitigation

---

### 🧠 Product

* Customer-specific tuning
* Alerting system
* Multi-tenant dashboards
* Compliance enforcement layer

---

### 💰 Strategic Expansion

**CHEQ + UserWay**

* Security + accessibility
* Litigation avoidance
* Upsell entry point

