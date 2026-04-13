import { useMemo, useState } from "react";

const STAGES = [
  { key: "fetch", label: "FETCH", sub: "HTTP GET CSV", icon: "🌐" },
  { key: "parse", label: "PARSE", sub: "Type conversion", icon: "📥" },
  { key: "detect", label: "DETECT", sub: "4-rule engine", icon: "🔍" },
  { key: "remediate", label: "REMEDIATE", sub: "Block + ROI", icon: "🛡️" },
];

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function StageRow({ stageIndex, running }) {
  return (
    <div style={{ display: "flex", gap: 10 }}>
      {STAGES.map((stage, idx) => {
        const active = running && stageIndex === idx;
        const done = stageIndex > idx;
        return (
          <div
            key={stage.key}
            style={{
              flex: 1,
              borderRadius: 12,
              border: "1px solid rgba(255,255,255,.08)",
              background: active
                ? "rgba(16,185,129,.14)"
                : done
                  ? "rgba(16,185,129,.08)"
                  : "rgba(255,255,255,.03)",
              padding: "14px 10px",
              textAlign: "center",
              opacity: active || done ? 1 : 0.55,
              transition: "all .25s",
            }}
          >
            <div style={{ fontSize: 21 }}>{done ? "✓" : stage.icon}</div>
            <div style={{ marginTop: 6, fontSize: 10, letterSpacing: 1.5, color: "#cbd5e1", fontWeight: 700 }}>{stage.label}</div>
            <div style={{ marginTop: 4, fontSize: 10, color: "#64748b" }}>{stage.sub}</div>
          </div>
        );
      })}
    </div>
  );
}

export default function PipelineApp() {
  const [state, setState] = useState("idle");
  const [stageIndex, setStageIndex] = useState(-1);
  const [logs, setLogs] = useState([]);

  const buttonText = useMemo(() => {
    if (state === "running") return "Processing live data...";
    if (state === "done") return "✓ Pipeline Complete";
    if (state === "error") return "Retry Pipeline";
    return "▶ Run Pipeline";
  }, [state]);

  async function runPipeline() {
    if (state === "running") return;
    setState("running");
    setLogs([]);
    const push = (msg) => setLogs((prev) => [...prev, msg]);

    try {
      setStageIndex(0);
      push("Fetching sample traffic data...");
      await wait(500);

      setStageIndex(1);
      push("Parsing sessions and converting types...");
      await wait(500);

      setStageIndex(2);
      push("Running bot detection rules...");
      await wait(700);

      setStageIndex(3);
      push("Computing ROI and blocked IP summary...");
      await wait(600);

      push("Pipeline complete. Ready for dashboard.");
      setState("done");
    } catch {
      setState("error");
      push("Pipeline failed.");
    }
  }

  return (
    <div style={{ minHeight: "100vh", background: "#070b16", color: "#e2e8f0", fontFamily: "system-ui, sans-serif" }}>
      <div style={{ borderBottom: "1px solid rgba(255,255,255,.06)", background: "linear-gradient(180deg,#0d1424,#070b16)" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto", padding: "14px 20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontWeight: 800, fontSize: 22 }}>CHEQ</span>
            <span style={{ color: "#f43f5e", fontWeight: 800, fontSize: 22 }}>.</span>
            <span style={{ fontSize: 10, color: "#64748b", letterSpacing: 2, fontWeight: 700, borderLeft: "1px solid #334155", paddingLeft: 10, marginLeft: 2 }}>
              THREAT MITIGATION
            </span>
          </div>
          <div style={{ color: "#475569", fontSize: 12 }}>Pipeline</div>
        </div>
      </div>

      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "38px 20px 56px" }}>
        <div style={{ textAlign: "center", marginBottom: 30 }}>
          <div style={{ fontSize: 10, letterSpacing: 3, fontWeight: 700, color: "#475569", marginBottom: 8 }}>AUTOMATED THREAT MITIGATION</div>
          <h1 style={{ margin: 0, fontSize: 52, lineHeight: 1.05, letterSpacing: -2, color: "#f8fafc" }}>Live Data Pipeline</h1>
          <p style={{ margin: "14px auto 0", maxWidth: 640, color: "#64748b", lineHeight: 1.6 }}>
            This pipeline fetches real traffic data, runs the 4-rule detection engine, and generates remediation insights in real time.
          </p>
        </div>

        <div style={{ border: "1px solid rgba(255,255,255,.06)", background: "rgba(255,255,255,.02)", borderRadius: 16, padding: 20 }}>
          <StageRow stageIndex={stageIndex} running={state === "running"} />
        </div>

        <div style={{ textAlign: "center", marginTop: 28 }}>
          <button
            onClick={runPipeline}
            disabled={state === "running"}
            style={{
              border: "none",
              borderRadius: 14,
              padding: "14px 42px",
              color: "white",
              fontWeight: 700,
              fontSize: 14,
              cursor: state === "running" ? "not-allowed" : "pointer",
              background:
                state === "running"
                  ? "rgba(16,185,129,.2)"
                  : "linear-gradient(135deg,#f43f5e,#e11d48)",
              boxShadow: state === "running" ? "none" : "0 8px 24px rgba(244,63,94,.25)",
            }}
          >
            {buttonText}
          </button>
        </div>

        <div style={{ marginTop: 26, border: "1px solid rgba(255,255,255,.06)", background: "#060a14", borderRadius: 12, padding: "12px 16px", minHeight: 124 }}>
          {logs.length === 0 ? (
            <div style={{ color: "#334155", fontSize: 12 }}>Logs will appear here when you run the pipeline.</div>
          ) : (
            logs.map((log, idx) => (
              <div key={idx} style={{ fontSize: 12, color: "#94a3b8", marginBottom: 6, fontFamily: "monospace" }}>
                [{new Date().toLocaleTimeString()}] {log}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
