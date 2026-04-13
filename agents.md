# Agent Quick Reference: Codebase Map

This document provides a structural map of the CHEQ Threat Mitigation Pipeline to help agents quickly ingest, navigate, and locate specific logic or components.

## 🏗️ Core Architecture
The application is a **linear 4-stage pipeline** (Fetch -> Parse -> Detect -> Remediate) that processes raw CSV traffic data into actionable security insights and financial ROI reports.

---

## 📍 File Reference

### 1. `src/App.jsx` (Primary Logic & UI)
This is the main application file containing the pipeline engine, state, and dashboard UI.

| Section | Location | Purpose |
| :--- | :--- | :--- |
| **Configuration** | `L24` | `DEFAULT_CONFIG` object (API endpoints, thresholds, weights). |
| **Pipeline Engine** | `L94` | Core logic (`parseCSV`, `findVelocityIPs`, `runDetection`, `runRemediation`). |
| **Constants & UI Mapping** | `L316` | UI metadata (`FLAG_INFO`, `COUNTRY_EMOJI`, `GEO`, `getVC`). |
| **Sub-Components** | `L352` | Modular elements (`AnimNum`, `PipelineViz`, `LogFeed`, `WorldMap`, `RuleTuner`, `ThreatModal`, `EmailPreview`). |
| **Root App Component** | `L763` | State management (`useCallback`, `runPipeline`) and conditional view rendering. |

### 2. `src/main.jsx`
- **Location:** Entry point.
- **Purpose:** Boots the React application and includes a global `ErrorBoundary` for stability.

### 3. `index.html`
- **Location:** Root.
- **Purpose:** Base HTML structure, including the `#root` mounting point and global CSS resets/styles.

### 4. `vite.config.js`
- **Location:** Root.
- **Purpose:** Build configuration. Includes the `base` path for GitHub Pages deployment (`/casestudycheq/`).

---

## 🛠️ Data Flow Summary
1. **Trigger:** User clicks "Run Pipeline" (or auto-run fires).
2. **Fetch:** `fetch(config.dataUrl)` retrieves CSV data.
3. **Parse:** `parseCSV()` cleans and normalizes types.
4. **Detect:** `runDetection()` applies the 4-rule weighted scoring engine.
5. **Remediate:** `runRemediation()` calculates money saved, ROI, and generates report metrics.
6. **Visualize:** Results populate the `Dashboard` views and `EmailPreview`.

## ⚙️ Key State Variables (in `App.jsx`)
- `config`: Current active settings (editable in Config tab).
- `pipelineState`: Lifecycle tracking (`idle` -> `running` -> `done`).
- `sessions`: Array of processed session objects with `risk_score` and `verdict`.
- `stats`: Aggregated metrics for charts and ROI.
- `auditTrail`: Persistent history of pipeline runs (stored in `localStorage`).
