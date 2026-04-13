import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import {
  PieChart, Pie, Cell, Tooltip as RTooltip,
  BarChart, Bar, XAxis, YAxis,
  ResponsiveContainer, AreaChart, Area
} from "recharts";

// ─── DEFAULT PIPELINE CONFIGURATION ─────────────────────────────
// This config drives the entire pipeline. Edit here or via the UI.
var DEFAULT_CONFIG = {
  dataUrl: "/api/cheq-csv",
  cpc: 5.0,
  botThreshold: 80,
  velocityLimit: 10,
  velocityWindow: 60,
  blockedCountries: ["China", "Russia"],
  botUserAgents: ["bot", "crawl", "spider", "scrapy", "python-requests", "curl", "wget", "httpclient", "libwww", "java/"],
  scores: { velocity: 45, impossible: 50, botUA: 45, geofence: 40 },
};

function buildUARegex(patterns) {
  if (!patterns || patterns.length === 0) return /^$/;
  var escaped = patterns.map(function(p) { return p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); });
  return new RegExp(escaped.join("|"), "i");
}

// ─── PIPELINE ENGINE (runs in browser) ──────────────────────────

function parseCSV(text) {
  var lines = text.trim().split("\n");
  if (lines.length < 2) return [];
  var headers = lines[0].split(",").map(function(h) { return h.trim(); });
  var sessions = [];
  for (var i = 1; i < lines.length; i++) {
    var vals = lines[i].split(",");
    if (vals.length < headers.length) continue;
    var row = {};
    for (var j = 0; j < headers.length; j++) {
      row[headers[j]] = (vals[j] || "").trim();
    }
    // Type conversions
    row.time_on_page = parseFloat(row.time_on_page) || 0;
    row.clicks = parseInt(row.clicks, 10) || 0;
    row.form_submitted = (row.form_submitted || "").toLowerCase() === "true";
    row.timestamp_raw = row.timestamp || "";
    try {
      row.timestamp_ms = new Date(row.timestamp).getTime();
    } catch (e) {
      row.timestamp_ms = Date.now();
    }
    sessions.push(row);
  }
  return sessions;
}

function findVelocityIPs(sessions, config) {
  // Group timestamps by IP
  var byIP = {};
  sessions.forEach(function(s) {
    if (!byIP[s.ip_address]) byIP[s.ip_address] = [];
    byIP[s.ip_address].push(s.timestamp_ms);
  });
  var flagged = new Set();
  Object.keys(byIP).forEach(function(ip) {
    var times = byIP[ip].sort(function(a, b) { return a - b; });
    for (var i = 0; i < times.length; i++) {
      var count = 1;
      for (var j = i + 1; j < times.length; j++) {
        if ((times[j] - times[i]) / 1000 <= config.velocityWindow) {
          count++;
        } else {
          break;
        }
      }
      if (count > config.velocityLimit) {
        flagged.add(ip);
        break;
      }
    }
  });
  return flagged;
}

function runDetection(sessions, config) {
  var velocityIPs = findVelocityIPs(sessions, config);
  var blockedSet = new Set(config.blockedCountries);
  var uaRegex = buildUARegex(config.botUserAgents);
  var sc = config.scores;

  sessions.forEach(function(s) {
    var score = 0;
    var flags = [];

    // Rule 1: Velocity
    if (velocityIPs.has(s.ip_address)) {
      score += sc.velocity;
      flags.push("velocity");
    }
    // Rule 2: Impossible behavior
    if (s.time_on_page === 0 && s.form_submitted) {
      score += sc.impossible;
      flags.push("impossible_behavior");
    }
    // Rule 3: Bot UA
    var ua = s.user_agent || "";
    if (!ua || uaRegex.test(ua)) {
      score += sc.botUA;
      flags.push("bot_ua");
    }
    // Rule 4: Geofence
    if (blockedSet.has((s.country || "").trim())) {
      score += sc.geofence;
      flags.push("geofenced");
    }

    s.risk_score = Math.min(score, 100);
    s.flags = flags;
    if (score > config.botThreshold) s.verdict = "Bot";
    else if (score > 0) s.verdict = "Suspicious";
    else s.verdict = "Valid";
  });
  return sessions;
}

function runRemediation(sessions, config) {
  var blocked = {};
  var totalSaved = 0;
  var formsBlocked = 0;
  var botClicks = 0;
  var validCount = 0;
  var suspCount = 0;
  var botCount = 0;
  var cpc = config.cpc;

  sessions.forEach(function(s) {
    if (s.verdict === "Valid") validCount++;
    else if (s.verdict === "Suspicious") suspCount++;
    else if (s.verdict === "Bot") {
      botCount++;
      var saved = s.clicks * cpc;
      totalSaved += saved;
      botClicks += s.clicks;
      if (s.form_submitted) formsBlocked++;
      if (!blocked[s.ip_address]) {
        blocked[s.ip_address] = {
          ip: s.ip_address,
          clicks: 0,
          saved: 0,
          flags: [],
          sessions: 0,
          country: s.country,
        };
      }
      blocked[s.ip_address].clicks += s.clicks;
      blocked[s.ip_address].saved += saved;
      blocked[s.ip_address].sessions++;
      s.flags.forEach(function(f) {
        if (blocked[s.ip_address].flags.indexOf(f) === -1) {
          blocked[s.ip_address].flags.push(f);
        }
      });
    }
  });

  var blockedList = Object.values(blocked).sort(function(a, b) { return b.saved - a.saved; });

  // Build hourly timeline
  var hourBuckets = {};
  for (var h = 0; h < 24; h++) {
    hourBuckets[h] = { Valid: 0, Suspicious: 0, Bot: 0 };
  }
  sessions.forEach(function(s) {
    try {
      var hour = new Date(s.timestamp_raw).getHours();
      if (!isNaN(hour) && hourBuckets[hour]) {
        hourBuckets[hour][s.verdict]++;
      }
    } catch (e) {}
  });
  var timeline = [];
  for (var hr = 0; hr < 24; hr += 2) {
    var label = String(hr).padStart(2, "0") + ":00";
    timeline.push({
      hour: label,
      Valid: (hourBuckets[hr]?.Valid || 0) + (hourBuckets[hr + 1]?.Valid || 0),
      Suspicious: (hourBuckets[hr]?.Suspicious || 0) + (hourBuckets[hr + 1]?.Suspicious || 0),
      Bot: (hourBuckets[hr]?.Bot || 0) + (hourBuckets[hr + 1]?.Bot || 0),
    });
  }

  // Count flag triggers
  var flagCounts = { bot_ua: 0, geofenced: 0, impossible_behavior: 0, velocity: 0 };
  sessions.forEach(function(s) {
    s.flags.forEach(function(f) { if (flagCounts[f] !== undefined) flagCounts[f]++; });
  });

  return {
    total: sessions.length,
    valid: validCount,
    suspicious: suspCount,
    bot: botCount,
    blockedIPs: blockedList,
    blockedCount: blockedList.length,
    saved: Math.round(totalSaved * 100) / 100,
    botClicks: botClicks,
    formsBlocked: formsBlocked,
    cpc: cpc,
    timeline: timeline,
    flagCounts: [
      { name: "Bot UA", count: flagCounts.bot_ua, color: "#a855f7" },
      { name: "Geofenced", count: flagCounts.geofenced, color: "#06b6d4" },
      { name: "Impossible", count: flagCounts.impossible_behavior, color: "#ef4444" },
      { name: "Velocity", count: flagCounts.velocity, color: "#f97316" },
    ],
    recentThreats: sessions
      .filter(function(s) { return s.verdict === "Bot"; })
      .sort(function(a, b) { return b.timestamp_ms - a.timestamp_ms; })
      .slice(0, 30),
  };
}

// ─── CONSTANTS ───────────────────────────────────────────────────
var FLAG_INFO = {
  velocity: { label: "Velocity Spike", color: "#f97316", desc: ">10 requests from same IP within 60s" },
  bot_ua: { label: "Bot User Agent", color: "#a855f7", desc: "UA matches known bot/crawler pattern" },
  impossible_behavior: { label: "Impossible Behavior", color: "#ef4444", desc: "0s on page but form was submitted" },
  geofenced: { label: "Geo-Blocked", color: "#06b6d4", desc: "Traffic from blocklisted country (CN/RU)" },
};

var COUNTRY_EMOJI = {
  "United States": "\uD83C\uDDFA\uD83C\uDDF8", "United Kingdom": "\uD83C\uDDEC\uD83C\uDDE7",
  Germany: "\uD83C\uDDE9\uD83C\uDDEA", Canada: "\uD83C\uDDE8\uD83C\uDDE6",
  Australia: "\uD83C\uDDE6\uD83C\uDDFA", India: "\uD83C\uDDEE\uD83C\uDDF3",
  Brazil: "\uD83C\uDDE7\uD83C\uDDF7", China: "\uD83C\uDDE8\uD83C\uDDF3",
  Russia: "\uD83C\uDDF7\uD83C\uDDFA", France: "\uD83C\uDDEB\uD83C\uDDF7",
  Japan: "\uD83C\uDDEF\uD83C\uDDF5",
};

var GEO = {
  "United States": [39.8, -98.6], "United Kingdom": [54.0, -2.0],
  Germany: [51.2, 10.4], Canada: [56.1, -106.3], Australia: [-25.3, 133.8],
  India: [20.6, 79.0], Brazil: [-14.2, -51.9], China: [35.9, 104.2],
  Russia: [61.5, 105.3], France: [46.6, 2.2], Japan: [36.2, 138.3],
};

function getVC(v) {
  if (v === "Bot") return "#ef4444";
  if (v === "Suspicious") return "#f59e0b";
  return "#10b981";
}

// ─── COMPONENTS ──────────────────────────────────────────────────

function AnimNum({ value, prefix, delay }) {
  var pfx = prefix || "";
  var dl = delay || 0;
  var ref = useRef({ started: false, val: 0 });
  var [display, setDisplay] = useState(0);

  useEffect(function() {
    var t = setTimeout(function() { ref.current.started = true; }, dl);
    return function() { clearTimeout(t); };
  }, [dl]);

  useEffect(function() {
    if (!ref.current.started) {
      var check = setInterval(function() {
        if (ref.current.started) {
          clearInterval(check);
          animate();
        }
      }, 50);
      return function() { clearInterval(check); };
    } else {
      animate();
    }
    function animate() {
      var start = performance.now();
      function tick(now) {
        var p = Math.min((now - start) / 1200, 1);
        var ease = 1 - Math.pow(1 - p, 3);
        setDisplay(Math.round(ease * value));
        if (p < 1) requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    }
  }, [value]);

  return pfx + display.toLocaleString();
}

// Pipeline stage visualization
var STAGES = [
  { key: "fetch", label: "FETCH", sub: "HTTP GET CSV" },
  { key: "parse", label: "PARSE", sub: "Type conversion" },
  { key: "detect", label: "DETECT", sub: "4-rule engine" },
  { key: "remediate", label: "REMEDIATE", sub: "Block + ROI" },
];
var STAGE_ICONS = ["\uD83C\uDF10", "\uD83D\uDCE5", "\uD83D\uDD0D", "\uD83D\uDEE1\uFE0F"];

function PipelineViz({ stageIdx, running }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", width: "100%", padding: "8px 0" }}>
      {STAGES.map(function(stage, i) {
        var isActive = running && i === stageIdx;
        var isDone = running ? i < stageIdx : stageIdx >= 3;
        return (
          <div key={stage.key} style={{ flex: 1, display: "flex", alignItems: "center" }}>
            <div style={{
              flex: 1, display: "flex", flexDirection: "column", alignItems: "center",
              gap: 7, opacity: isDone || isActive ? 1 : 0.28, transition: "all .5s",
            }}>
              <div style={{
                width: 52, height: 52, borderRadius: 14,
                background: isActive ? "rgba(16,185,129,.12)" : isDone ? "rgba(16,185,129,.06)" : "rgba(255,255,255,.03)",
                border: isActive ? "2px solid #10b981" : isDone ? "2px solid rgba(16,185,129,.35)" : "2px solid rgba(255,255,255,.05)",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 22, transition: "all .4s",
                boxShadow: isActive ? "0 0 24px rgba(16,185,129,.3)" : "none",
              }}>
                {isDone ? "\u2713" : STAGE_ICONS[i]}
              </div>
              <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: 1.8, color: isActive ? "#10b981" : isDone ? "#6ee7b7" : "#475569" }}>
                {stage.label}
              </span>
              <span style={{ fontSize: 9, color: "#475569", textAlign: "center" }}>{stage.sub}</span>
            </div>
            {i < 3 && (
              <div style={{
                width: 48, height: 2, margin: "0 -6px",
                background: isDone ? "#10b981" : isActive ? "linear-gradient(90deg,#10b981 40%,transparent)" : "rgba(255,255,255,.04)",
                borderRadius: 1, transition: "all .5s", marginBottom: 38,
              }} />
            )}
          </div>
        );
      })}
    </div>
  );
}

// Log feed
function LogFeed({ logs }) {
  var ref = useRef(null);
  var LEVEL_COLORS = { info: "#94a3b8", warn: "#f59e0b", error: "#ef4444", success: "#10b981" };
  useEffect(function() {
    if (ref.current) ref.current.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
  }, [logs]);
  if (!logs || logs.length === 0) return null;
  return (
    <div ref={ref} style={{
      fontFamily: "monospace", fontSize: 11, lineHeight: 1.9,
      background: "#060a14", borderRadius: 12, padding: "14px 16px",
      maxHeight: 280, overflowY: "auto", border: "1px solid rgba(255,255,255,.05)",
    }}>
      {logs.map(function(entry, idx) {
        return (
          <div key={idx} style={{ animation: "fadeIn .25s ease" }}>
            <span style={{ color: "#334155" }}>[{entry.time}]</span>{" "}
            <span style={{ color: LEVEL_COLORS[entry.level] || "#94a3b8", fontWeight: entry.level !== "info" ? 600 : 400 }}>
              {entry.msg}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// World map
function WorldMap({ threats }) {
  if (!threats || threats.length === 0) return null;
  var countries = {};
  threats.forEach(function(t) { countries[t.country] = (countries[t.country] || 0) + 1; });

  function project(lat, lng) {
    var x = (lng + 180) * (800 / 360);
    var latRad = (lat * Math.PI) / 180;
    var mercN = Math.log(Math.tan(Math.PI / 4 + latRad / 2));
    var y = 200 - (800 * mercN) / (2 * Math.PI);
    return [x, y];
  }
  var hq = project(39.8, -98.6);

  return (
    <div style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, padding: "20px 22px", border: "1px solid rgba(255,255,255,.04)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <div style={{ fontSize: 13, fontWeight: 700 }}>Threat Origins</div>
        <div style={{ display: "flex", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#ef4444" }} />
            <span style={{ fontSize: 10, color: "#64748b" }}>Attack source</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#10b981" }} />
            <span style={{ fontSize: 10, color: "#64748b" }}>TechCorp HQ</span>
          </div>
        </div>
      </div>
      <svg viewBox="0 0 800 400" style={{ width: "100%", height: "auto", display: "block" }}>
        <defs>
          <radialGradient id="glR"><stop offset="0%" stopColor="#ef4444" stopOpacity="0.5" /><stop offset="100%" stopColor="#ef4444" stopOpacity="0" /></radialGradient>
          <radialGradient id="glG"><stop offset="0%" stopColor="#10b981" stopOpacity="0.5" /><stop offset="100%" stopColor="#10b981" stopOpacity="0" /></radialGradient>
        </defs>
        {[100,200,300].map(function(y) { return <line key={"h"+y} x1={0} y1={y} x2={800} y2={y} stroke="rgba(255,255,255,.03)" />; })}
        {[200,400,600].map(function(x) { return <line key={"v"+x} x1={x} y1={0} x2={x} y2={400} stroke="rgba(255,255,255,.03)" />; })}
        {Object.keys(countries).map(function(c) {
          var coords = GEO[c]; if (!coords) return null;
          var pt = project(coords[0], coords[1]);
          return (
            <g key={c}>
              <line x1={pt[0]} y1={pt[1]} x2={hq[0]} y2={hq[1]} stroke="rgba(239,68,68,.25)" strokeWidth={1} strokeDasharray="4 4" />
              <circle cx={pt[0]} cy={pt[1]} r={20} fill="url(#glR)" />
              <circle cx={pt[0]} cy={pt[1]} r={4} fill="#ef4444" />
              <text x={pt[0]} y={pt[1]-12} fill="#ef4444" fontSize={9} fontWeight={700} textAnchor="middle">{c}</text>
              <text x={pt[0]} y={pt[1]+14} fill="#94a3b8" fontSize={8} textAnchor="middle">{countries[c]} hits</text>
            </g>
          );
        })}
        <circle cx={hq[0]} cy={hq[1]} r={24} fill="url(#glG)" />
        <circle cx={hq[0]} cy={hq[1]} r={5} fill="#10b981" />
        <text x={hq[0]} y={hq[1]-14} fill="#10b981" fontSize={9} fontWeight={700} textAnchor="middle">TechCorp HQ</text>
      </svg>
    </div>
  );
}

// Rule tuner
function RuleTuner({ sessions }) {
  var [velW, setVelW] = useState(45);
  var [velT, setVelT] = useState(10);
  var [geoOn, setGeoOn] = useState(true);
  var [botOn, setBotOn] = useState(true);
  var [impOn, setImpOn] = useState(true);

  var results = useMemo(function() {
    if (!sessions || sessions.length === 0) return { bot: 0, susp: 0, saved: 0, forms: 0 };
    var botC = 0, suspC = 0, savedA = 0, formsC = 0;
    sessions.forEach(function(s) {
      var score = 0;
      if (s.flags && s.flags.indexOf("velocity") !== -1 && velT <= 15) score += velW;
      if (s.flags && s.flags.indexOf("bot_ua") !== -1 && botOn) score += 45;
      if (s.flags && s.flags.indexOf("impossible_behavior") !== -1 && impOn) score += 50;
      if (s.flags && s.flags.indexOf("geofenced") !== -1 && geoOn) score += 40;
      if (score > 80) { botC++; savedA += s.clicks * (config?.cpc || 5); if (s.form_submitted) formsC++; }
      else if (score > 0) suspC++;
    });
    return { bot: botC, susp: suspC, saved: Math.round(savedA), forms: formsC };
  }, [sessions, velW, velT, geoOn, botOn, impOn]);

  return (
    <div style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, padding: "20px 22px", border: "1px solid rgba(255,255,255,.04)" }}>
      <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>Rule Tuning</div>
      <div style={{ fontSize: 11, color: "#475569", marginBottom: 18 }}>Adjust thresholds to see detection impact on real data</div>
      {[
        ["Velocity Weight", velW, setVelW, 0, 100, "pts", "#f97316"],
        ["Velocity Threshold", velT, setVelT, 3, 30, " req/min", "#f97316"],
      ].map(function(args) {
        return (
          <div key={args[0]} style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
              <span style={{ fontSize: 11, color: "#94a3b8", fontWeight: 600 }}>{args[0]}</span>
              <span style={{ fontSize: 11, fontFamily: "monospace", color: args[6] }}>{args[1]}{args[5]}</span>
            </div>
            <input type="range" min={args[3]} max={args[4]} value={args[1]}
              onChange={function(e) { args[2](Number(e.target.value)); }}
              style={{ width: "100%", accentColor: args[6] }} />
          </div>
        );
      })}
      {[
        ["Geofence (CN, RU)", geoOn, setGeoOn, "#06b6d4"],
        ["Bot UA Detection", botOn, setBotOn, "#a855f7"],
        ["Impossible Behavior", impOn, setImpOn, "#ef4444"],
      ].map(function(args) {
        return (
          <div key={args[0]} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <span style={{ fontSize: 11, color: "#94a3b8", fontWeight: 600 }}>{args[0]}</span>
            <button onClick={function() { args[2](!args[1]); }} style={{
              width: 40, height: 22, borderRadius: 11, border: "none", cursor: "pointer",
              background: args[1] ? args[3] : "rgba(255,255,255,.08)", position: "relative", transition: "all .2s",
            }}>
              <div style={{ width: 16, height: 16, borderRadius: 8, background: "#fff", position: "absolute", top: 3, left: args[1] ? 21 : 3, transition: "all .2s", boxShadow: "0 1px 3px rgba(0,0,0,.3)" }} />
            </button>
          </div>
        );
      })}
      <div style={{ marginTop: 18, padding: "14px 16px", background: "rgba(255,255,255,.03)", borderRadius: 10, border: "1px solid rgba(255,255,255,.04)" }}>
        <div style={{ fontSize: 10, color: "#475569", letterSpacing: 1.5, fontWeight: 700, marginBottom: 10 }}>PROJECTED RESULTS</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          <div><div style={{ fontSize: 9, color: "#475569" }}>BOTS CAUGHT</div><div style={{ fontSize: 20, fontWeight: 800, color: "#ef4444" }}>{results.bot}</div></div>
          <div><div style={{ fontSize: 9, color: "#475569" }}>MONEY SAVED</div><div style={{ fontSize: 20, fontWeight: 800, color: "#10b981" }}>${results.saved.toLocaleString()}</div></div>
          <div><div style={{ fontSize: 9, color: "#475569" }}>SUSPICIOUS</div><div style={{ fontSize: 20, fontWeight: 800, color: "#f59e0b" }}>{results.susp}</div></div>
          <div><div style={{ fontSize: 9, color: "#475569" }}>FORMS BLOCKED</div><div style={{ fontSize: 20, fontWeight: 800, color: "#f59e0b" }}>{results.forms}</div></div>
        </div>
      </div>
    </div>
  );
}

// Threat modal
function ThreatModal({ session, onClose }) {
  if (!session) return null;
  var vc = getVC(session.verdict);
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 100, background: "rgba(0,0,0,.7)", backdropFilter: "blur(10px)", display: "flex", alignItems: "center", justifyContent: "center", animation: "fadeIn .2s" }} onClick={onClose}>
      <div onClick={function(e) { e.stopPropagation(); }} style={{ background: "#0c1225", border: "1px solid rgba(255,255,255,.08)", borderRadius: 18, padding: "26px 28px", maxWidth: 520, width: "92%", maxHeight: "88vh", overflowY: "auto", animation: "slideUp .3s" }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
          <div>
            <div style={{ fontSize: 10, color: "#475569", letterSpacing: 2, fontWeight: 700, marginBottom: 5 }}>THREAT INVESTIGATION</div>
            <div style={{ fontSize: 18, fontWeight: 700, color: "#f1f5f9", fontFamily: "monospace" }}>{session.ip_address}</div>
          </div>
          <button onClick={onClose} style={{ background: "rgba(255,255,255,.05)", border: "none", color: "#94a3b8", width: 32, height: 32, borderRadius: 10, cursor: "pointer", fontSize: 14 }}>{"\u2715"}</button>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16, background: "rgba(255,255,255,.03)", borderRadius: 12, padding: "14px 16px", marginBottom: 16 }}>
          <div style={{ position: "relative", width: 58, height: 58 }}>
            <svg viewBox="0 0 36 36" style={{ width: 58, height: 58, transform: "rotate(-90deg)" }}>
              <circle cx="18" cy="18" r="14" fill="none" stroke="rgba(255,255,255,.06)" strokeWidth="3" />
              <circle cx="18" cy="18" r="14" fill="none" stroke={vc} strokeWidth="3" strokeDasharray={String(session.risk_score * 0.88) + " 88"} strokeLinecap="round" />
            </svg>
            <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 15, fontWeight: 800, color: vc, fontFamily: "monospace" }}>{session.risk_score}</div>
          </div>
          <div>
            <div style={{ fontSize: 17, fontWeight: 700, color: vc }}>{session.verdict}</div>
            <div style={{ fontSize: 11, color: "#64748b" }}>Risk {session.risk_score}/100</div>
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 16 }}>
          {[
            { l: "Country", v: (COUNTRY_EMOJI[session.country] || "") + " " + (session.country || "") },
            { l: "Device", v: session.device_type || "Unknown" },
            { l: "Clicks", v: String(session.clicks) },
            { l: "Wasted", v: "$" + (session.clicks * (stats?.cpc || 5)).toLocaleString(), c: "#ef4444" },
            { l: "Page", v: session.page_url || "" },
            { l: "Time on Page", v: session.time_on_page + "s", c: session.time_on_page === 0 ? "#ef4444" : undefined },
          ].map(function(f) {
            return (
              <div key={f.l} style={{ background: "rgba(255,255,255,.025)", borderRadius: 8, padding: "8px 12px" }}>
                <div style={{ fontSize: 9, color: "#475569", textTransform: "uppercase" }}>{f.l}</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: f.c || "#cbd5e1" }}>{f.v}</div>
              </div>
            );
          })}
        </div>
        <div style={{ fontSize: 9, color: "#475569", letterSpacing: 2, fontWeight: 700, marginBottom: 8 }}>FLAGS</div>
        {(!session.flags || session.flags.length === 0) && <div style={{ color: "#334155", fontSize: 12, fontStyle: "italic", marginBottom: 12 }}>No flags</div>}
        {(session.flags || []).map(function(f) {
          var info = FLAG_INFO[f]; if (!info) return null;
          return (
            <div key={f} style={{ display: "flex", alignItems: "center", gap: 10, background: info.color + "0a", borderRadius: 10, padding: "9px 13px", borderLeft: "3px solid " + info.color, marginBottom: 6 }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: info.color }}>{info.label}</div>
                <div style={{ fontSize: 10, color: "#64748b" }}>{info.desc}</div>
              </div>
            </div>
          );
        })}
        <div style={{ fontSize: 9, color: "#475569", letterSpacing: 2, fontWeight: 700, marginBottom: 5, marginTop: 14 }}>USER AGENT</div>
        <div style={{ fontFamily: "monospace", fontSize: 10, color: "#64748b", background: "rgba(255,255,255,.025)", borderRadius: 8, padding: "9px 13px", wordBreak: "break-all" }}>
          {session.user_agent || <span style={{ color: "#ef4444", fontStyle: "italic" }}>empty</span>}
        </div>
        {session.verdict === "Bot" && (
          <div style={{ marginTop: 14, background: "rgba(239,68,68,.06)", borderRadius: 12, padding: "12px 14px", border: "1px solid rgba(239,68,68,.12)" }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#fca5a5" }}>IP Blocked</div>
            <div style={{ fontSize: 10, color: "#64748b" }}>${(session.clicks * (stats?.cpc || 5)).toLocaleString()} saved</div>
          </div>
        )}
      </div>
    </div>
  );
}

// Email preview
function EmailPreview({ stats }) {
  var [copied, setCopied] = useState(false);
  if (!stats) return null;
  var pct = ((stats.bot + stats.suspicious) / stats.total * 100).toFixed(0);
  var annual = (stats.saved * 365).toLocaleString();
  var body = "Subject: Traffic Analysis Results \u2014 $" + stats.saved.toLocaleString() + " in Bot Spend Identified\n\nDear CTO,\n\nWe ran your recent traffic (" + stats.total + " sessions) through our automated threat detection pipeline and identified that approximately " + pct + "% of your traffic is either confirmed bot activity or suspicious. In this sample, " + stats.bot + " sessions exceeded our bot threshold, generating " + stats.botClicks + " fraudulent clicks and " + stats.formsBlocked + " fake form submissions \u2014 translating to $" + stats.saved.toLocaleString() + " in wasted ad spend.\n\nThe most common attack vectors were:\n\u2022 Bot user agents (scrapers, crawlers) \u2014 " + stats.flagCounts[0].count + " detections\n\u2022 Geofenced traffic from China & Russia \u2014 " + stats.flagCounts[1].count + " detections\n\u2022 Impossible form submissions (0s page time) \u2014 " + stats.flagCounts[2].count + " detections\n\u2022 Velocity flooding (>10 req/min) \u2014 " + stats.flagCounts[3].count + " detections\n\nAt this rate, your annualized exposure exceeds $" + annual + ". We have compiled a blocklist of " + stats.blockedCount + " offending IPs and can have automated protection running within days.\n\nBest regards,\n[Your Name]\nCustomer Success Engineering, CHEQ";
  return (
    <div style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, border: "1px solid rgba(255,255,255,.04)", overflow: "hidden" }}>
      <div style={{ padding: "16px 22px", display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid rgba(255,255,255,.04)" }}>
        <div style={{ fontSize: 13, fontWeight: 700 }}>Customer Email (auto-generated from real data)</div>
        <button onClick={function() { try { navigator.clipboard.writeText(body); } catch(e) {} setCopied(true); setTimeout(function() { setCopied(false); }, 2000); }} style={{
          padding: "6px 16px", borderRadius: 8, border: "none", cursor: "pointer", fontSize: 11, fontWeight: 600,
          background: copied ? "rgba(16,185,129,.15)" : "rgba(255,255,255,.06)", color: copied ? "#10b981" : "#94a3b8",
        }}>{copied ? "\u2713 Copied" : "Copy Email"}</button>
      </div>
      <div style={{ padding: "18px 22px" }}>
        <div style={{ background: "#0a0f1a", borderRadius: 10, padding: "18px 20px", fontFamily: "monospace", fontSize: 11, color: "#94a3b8", lineHeight: 1.8, whiteSpace: "pre-wrap", border: "1px solid rgba(255,255,255,.04)", maxHeight: 340, overflowY: "auto" }}>
          {body}
        </div>
      </div>
    </div>
  );
}

// ─── MAIN APP ────────────────────────────────────────────────────
export default function App() {
  // Pipeline config (editable before running)
  var [config, setConfig] = useState(JSON.parse(JSON.stringify(DEFAULT_CONFIG)));

  // Pipeline state
  var [pipelineState, setPipelineState] = useState("idle"); // idle | running | done | error
  var [stageIdx, setStageIdx] = useState(-1);
  var [logs, setLogs] = useState([]);
  var [sessions, setSessions] = useState(null);
  var [stats, setStats] = useState(null);
  var [errorMsg, setErrorMsg] = useState("");

  // UI state
  var [view, setView] = useState("pipeline");
  var [dashTab, setDashTab] = useState("overview");
  var [filter, setFilter] = useState("all");
  var [selectedSession, setSelectedSession] = useState(null);

  function addLog(msg, level) {
    var time = new Date().toLocaleTimeString("en-US", { hour12: false });
    setLogs(function(prev) { return prev.concat([{ time: time, msg: msg, level: level || "info" }]); });
  }

  var runPipeline = useCallback(function() {
    setPipelineState("running");
    setLogs([]);
    setStageIdx(0);
    addLog("Pipeline config: " + config.blockedCountries.length + " geofenced countries, " + config.botUserAgents.length + " bot UA patterns, $" + config.cpc + " CPC", "info");
    addLog("Fetching from " + config.dataUrl, "info");

    // Stage 0: FETCH
    fetch(config.dataUrl)
      .then(function(response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        addLog("HTTP " + response.status + " \u2014 downloading CSV...", "info");
        return response.text();
      })
      .then(function(csvText) {
        if (!csvText || csvText.trim().charAt(0) === "<") {
          throw new Error("CHEQ endpoint returned non-CSV content");
        }
        addLog("Received " + csvText.length.toLocaleString() + " bytes", "success");

        // Stage 1: PARSE
        setStageIdx(1);
        addLog("Parsing CSV \u2014 converting types...", "info");
        var parsed = parseCSV(csvText);
        addLog("Parsed " + parsed.length + " sessions", "success");

        // Stage 2: DETECT
        setTimeout(function() {
          setStageIdx(2);
          addLog("Running detection with config: velocity>" + config.velocityLimit + "req/" + config.velocityWindow + "s, threshold>" + config.botThreshold, "info");
          var detected = runDetection(parsed, config);

          var bots = detected.filter(function(s) { return s.verdict === "Bot"; });
          var susp = detected.filter(function(s) { return s.verdict === "Suspicious"; });
          addLog("DETECT complete: " + bots.length + " bots, " + susp.length + " suspicious", "info");

          bots.slice(0, 5).forEach(function(b) {
            addLog("BLOCK  " + b.ip_address + " \u2014 [" + b.flags.join(", ") + "] score:" + b.risk_score, "error");
          });
          if (bots.length > 5) addLog("... and " + (bots.length - 5) + " more blocked", "error");

          // Stage 3: REMEDIATE
          setTimeout(function() {
            setStageIdx(3);
            addLog("Running remediation \u2014 blocking IPs, calculating ROI...", "info");
            var result = runRemediation(detected, config);

            addLog("Blocked " + result.blockedCount + " unique IPs", "info");
            addLog("Saved: $" + result.saved.toLocaleString() + " (" + result.botClicks + " clicks x $" + config.cpc + " CPC)", "success");
            addLog(result.formsBlocked + " fake form submissions intercepted", "success");
            addLog("Pipeline complete \u2713 \u2014 all data processed from live endpoint", "success");

            setSessions(detected);
            setStats(result);

            setTimeout(function() {
              setPipelineState("done");
            }, 600);
          }, 800);
        }, 800);
      })
      .catch(function(err) {
        addLog("ERROR: " + err.message, "error");
        addLog("Try refreshing or check if the endpoint is accessible", "warn");
        setErrorMsg(err.message);
        setPipelineState("error");
      });
  }, [config]);

  var filteredSessions = useMemo(function() {
    if (!sessions) return [];
    if (filter === "all") return sessions;
    return sessions.filter(function(s) { return s.verdict.toLowerCase() === filter; });
  }, [sessions, filter]);

  var pieData = stats ? [
    { name: "Valid", value: stats.valid },
    { name: "Suspicious", value: stats.suspicious },
    { name: "Bot", value: stats.bot },
  ] : [];
  var PIE_COLORS = ["#10b981", "#f59e0b", "#ef4444"];
  var ttStyle = { background: "#151d30", border: "1px solid rgba(255,255,255,.08)", borderRadius: 8, fontSize: 12, color: "#e2e8f0" };

  return (
    <div>
      <style>{`
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px) } to { opacity: 1; transform: none } }
        @keyframes slideUp { from { opacity: 0; transform: translateY(24px) } to { opacity: 1; transform: none } }
        @keyframes slideIn { from { opacity: 0; transform: translateX(-12px) } to { opacity: 1; transform: none } }
        * { box-sizing: border-box; }
      `}</style>
      <div style={{ fontFamily: "system-ui, sans-serif", background: "#070b16", minHeight: "100vh", color: "#e2e8f0" }}>

        {/* HEADER */}
        <div style={{ background: "linear-gradient(180deg,#0d1424,#070b16)", borderBottom: "1px solid rgba(255,255,255,.04)", padding: "14px 24px", position: "sticky", top: 0, zIndex: 50 }}>
          <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ fontSize: 22, fontWeight: 800, color: "#f1f5f9", letterSpacing: -1 }}>CHEQ</span>
              <span style={{ fontSize: 22, fontWeight: 800, color: "#f43f5e", marginLeft: -9 }}>.</span>
              <span style={{ fontSize: 10, color: "#334155", letterSpacing: 2.5, fontWeight: 700, marginLeft: 6, borderLeft: "1px solid #1e293b", paddingLeft: 12 }}>THREAT MITIGATION</span>
            </div>
            <div style={{ display: "flex", gap: 3, background: "rgba(255,255,255,.03)", borderRadius: 10, padding: 3 }}>
              {[["pipeline","Pipeline"],["config","Config"],["dashboard","Dashboard"],["email","Email"]].map(function(pair) {
                var disabled = (pair[0] === "dashboard" || pair[0] === "email") && pipelineState !== "done";
                return (
                  <button key={pair[0]} onClick={function() { if (!disabled) setView(pair[0]); }} style={{
                    padding: "7px 18px", borderRadius: 8, border: "none", cursor: disabled ? "not-allowed" : "pointer",
                    fontSize: 12, fontWeight: 600, opacity: disabled ? 0.35 : 1,
                    background: view === pair[0] ? "rgba(255,255,255,.08)" : "transparent",
                    color: view === pair[0] ? "#f1f5f9" : "#475569", transition: "all .2s",
                  }}>{pair[1]}</button>
                );
              })}
            </div>
          </div>
        </div>

        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "28px 24px 64px" }}>

          {/* PIPELINE */}
          {view === "pipeline" && (
            <div style={{ animation: "fadeIn .4s" }}>
              <div style={{ textAlign: "center", marginBottom: 44 }}>
                <div style={{ fontSize: 10, color: "#475569", letterSpacing: 3, fontWeight: 700, marginBottom: 10 }}>AUTOMATED THREAT MITIGATION</div>
                <h1 style={{ fontSize: 36, fontWeight: 800, letterSpacing: -2, color: "#f1f5f9", marginBottom: 14 }}>Live Data Pipeline</h1>
                <div style={{ fontSize: 14, color: "#64748b", maxWidth: 560, margin: "0 auto", lineHeight: 1.6 }}>
                  This pipeline fetches <strong style={{ color: "#94a3b8" }}>real traffic data</strong> from the CHEQ endpoint, runs the full 4-rule detection engine in your browser, and generates all results live.
                </div>
              </div>

              <div style={{ background: "rgba(255,255,255,.015)", borderRadius: 18, padding: "30px 28px", border: "1px solid rgba(255,255,255,.04)", marginBottom: 28 }}>
                <PipelineViz stageIdx={stageIdx} running={pipelineState === "running"} />
              </div>

              <div style={{ textAlign: "center", marginBottom: 28 }}>
                {pipelineState === "error" && (
                  <div style={{ marginBottom: 16, color: "#ef4444", fontSize: 12 }}>
                    Failed to fetch data: {errorMsg}. The CHEQ endpoint may be temporarily unavailable.
                  </div>
                )}
                <button onClick={pipelineState === "done" ? function() { setView("dashboard"); } : runPipeline}
                  disabled={pipelineState === "running"}
                  style={{
                    padding: "15px 44px", borderRadius: 14, border: "none",
                    cursor: pipelineState === "running" ? "not-allowed" : "pointer",
                    fontSize: 14, fontWeight: 700, color: "#fff",
                    background: pipelineState === "running" ? "rgba(16,185,129,.12)" : pipelineState === "done" ? "linear-gradient(135deg,#10b981,#059669)" : "linear-gradient(135deg,#f43f5e,#e11d48)",
                    boxShadow: pipelineState === "running" ? "none" : "0 4px 24px rgba(244,63,94,.25)",
                    transition: "all .3s",
                  }}>
                  {pipelineState === "running" ? "Processing live data..." : pipelineState === "done" ? "\u2713 View Dashboard" : pipelineState === "error" ? "Retry Pipeline" : "\u25B6 Run Pipeline"}
                </button>
              </div>

              <LogFeed logs={logs} />

              {pipelineState === "done" && stats && (
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14, marginTop: 28, animation: "fadeIn .6s" }}>
                  {[
                    { l: "Sessions", v: stats.total, c: "#6366f1" },
                    { l: "Threats", v: stats.bot, c: "#ef4444" },
                    { l: "IPs Blocked", v: stats.blockedCount, c: "#f97316" },
                    { l: "Money Saved", v: stats.saved, p: "$", c: "#10b981" },
                  ].map(function(item, i) {
                    return (
                      <div key={item.l} style={{ background: item.c + "08", borderRadius: 14, padding: "20px 18px", border: "1px solid " + item.c + "18", textAlign: "center" }}>
                        <div style={{ fontSize: 30, fontWeight: 800, color: item.c, letterSpacing: -1.5 }}>
                          <AnimNum value={item.v} prefix={item.p} delay={i * 200} />
                        </div>
                        <div style={{ fontSize: 11, color: "#475569", marginTop: 5 }}>{item.l}</div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* CONFIG EDITOR */}
          {view === "config" && (
            <div style={{ animation: "fadeIn .4s", maxWidth: 800, margin: "0 auto" }}>
              <div style={{ marginBottom: 28 }}>
                <div style={{ fontSize: 10, color: "#475569", letterSpacing: 3, fontWeight: 700, marginBottom: 10 }}>PIPELINE CONFIGURATION</div>
                <h1 style={{ fontSize: 32, fontWeight: 800, letterSpacing: -1.5, color: "#f1f5f9", marginBottom: 8 }}>Detection Rules</h1>
                <div style={{ fontSize: 13, color: "#64748b", lineHeight: 1.6 }}>
                  Edit these settings before running the pipeline. Changes are applied when you click Run Pipeline.
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                {/* Left column: Thresholds */}
                <div style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, padding: "22px 24px", border: "1px solid rgba(255,255,255,.04)" }}>
                  <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 18 }}>Thresholds</div>

                  {[
                    { label: "Cost Per Click (CPC)", key: "cpc", unit: "$", min: 0.5, max: 50, step: 0.5, color: "#10b981" },
                    { label: "Bot Score Threshold", key: "botThreshold", unit: "pts", min: 20, max: 100, step: 5, color: "#ef4444" },
                    { label: "Velocity Limit", key: "velocityLimit", unit: " req", min: 3, max: 50, step: 1, color: "#f97316" },
                    { label: "Velocity Window", key: "velocityWindow", unit: "s", min: 10, max: 300, step: 10, color: "#f97316" },
                  ].map(function(item) {
                    return (
                      <div key={item.key} style={{ marginBottom: 16 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                          <span style={{ fontSize: 11, color: "#94a3b8", fontWeight: 600 }}>{item.label}</span>
                          <span style={{ fontSize: 12, fontFamily: "monospace", color: item.color, fontWeight: 700 }}>
                            {item.key === "cpc" ? "$" : ""}{config[item.key]}{item.key !== "cpc" ? item.unit : ""}
                          </span>
                        </div>
                        <input type="range" min={item.min} max={item.max} step={item.step} value={config[item.key]}
                          onChange={function(e) {
                            var val = Number(e.target.value);
                            setConfig(function(prev) { var next = JSON.parse(JSON.stringify(prev)); next[item.key] = val; return next; });
                          }}
                          style={{ width: "100%", accentColor: item.color }} />
                      </div>
                    );
                  })}

                  <div style={{ marginTop: 12 }}>
                    <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12 }}>Score Weights</div>
                    {[
                      { label: "Velocity Score", key: "velocity", color: "#f97316" },
                      { label: "Impossible Behavior Score", key: "impossible", color: "#ef4444" },
                      { label: "Bot UA Score", key: "botUA", color: "#a855f7" },
                      { label: "Geofence Score", key: "geofence", color: "#06b6d4" },
                    ].map(function(item) {
                      return (
                        <div key={item.key} style={{ marginBottom: 14 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                            <span style={{ fontSize: 11, color: "#94a3b8", fontWeight: 600 }}>{item.label}</span>
                            <span style={{ fontSize: 12, fontFamily: "monospace", color: item.color, fontWeight: 700 }}>{config.scores[item.key]}pts</span>
                          </div>
                          <input type="range" min={0} max={100} value={config.scores[item.key]}
                            onChange={function(e) {
                              var val = Number(e.target.value);
                              var scoreKey = item.key;
                              setConfig(function(prev) { var next = JSON.parse(JSON.stringify(prev)); next.scores[scoreKey] = val; return next; });
                            }}
                            style={{ width: "100%", accentColor: item.color }} />
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Right column: Lists */}
                <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                  {/* Geofenced Countries */}
                  <div style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, padding: "22px 24px", border: "1px solid rgba(255,255,255,.04)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                      <div style={{ fontSize: 13, fontWeight: 700 }}>Blocked Countries</div>
                      <span style={{ fontSize: 10, color: "#06b6d4", fontWeight: 600 }}>{config.blockedCountries.length} active</span>
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 12 }}>
                      {config.blockedCountries.map(function(country, idx) {
                        return (
                          <span key={idx} style={{
                            display: "flex", alignItems: "center", gap: 6,
                            padding: "5px 12px", borderRadius: 8,
                            background: "rgba(6,182,212,.08)", border: "1px solid rgba(6,182,212,.2)",
                            fontSize: 12, color: "#06b6d4", fontWeight: 600,
                          }}>
                            {COUNTRY_EMOJI[country] || ""} {country}
                            <button onClick={function() {
                              setConfig(function(prev) {
                                var next = JSON.parse(JSON.stringify(prev));
                                next.blockedCountries = next.blockedCountries.filter(function(c) { return c !== country; });
                                return next;
                              });
                            }} style={{ background: "none", border: "none", color: "#ef4444", cursor: "pointer", fontSize: 12, padding: 0, marginLeft: 2 }}>{"\u2715"}</button>
                          </span>
                        );
                      })}
                    </div>
                    <div style={{ display: "flex", gap: 6 }}>
                      <input id="newCountry" type="text" placeholder="Add country..." style={{
                        flex: 1, padding: "7px 12px", borderRadius: 8, border: "1px solid rgba(255,255,255,.08)",
                        background: "rgba(255,255,255,.03)", color: "#e2e8f0", fontSize: 12, outline: "none",
                      }} onKeyDown={function(e) {
                        if (e.key === "Enter" && e.target.value.trim()) {
                          var val = e.target.value.trim();
                          setConfig(function(prev) {
                            var next = JSON.parse(JSON.stringify(prev));
                            if (next.blockedCountries.indexOf(val) === -1) next.blockedCountries.push(val);
                            return next;
                          });
                          e.target.value = "";
                        }
                      }} />
                      <button onClick={function() {
                        var input = document.getElementById("newCountry");
                        if (input && input.value.trim()) {
                          var val = input.value.trim();
                          setConfig(function(prev) {
                            var next = JSON.parse(JSON.stringify(prev));
                            if (next.blockedCountries.indexOf(val) === -1) next.blockedCountries.push(val);
                            return next;
                          });
                          input.value = "";
                        }
                      }} style={{
                        padding: "7px 14px", borderRadius: 8, border: "none", cursor: "pointer",
                        background: "#06b6d4", color: "#fff", fontSize: 11, fontWeight: 600,
                      }}>Add</button>
                    </div>
                  </div>

                  {/* Bot User Agents */}
                  <div style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, padding: "22px 24px", border: "1px solid rgba(255,255,255,.04)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                      <div style={{ fontSize: 13, fontWeight: 700 }}>Bot UA Patterns</div>
                      <span style={{ fontSize: 10, color: "#a855f7", fontWeight: 600 }}>{config.botUserAgents.length} patterns</span>
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 12 }}>
                      {config.botUserAgents.map(function(pattern, idx) {
                        return (
                          <span key={idx} style={{
                            display: "flex", alignItems: "center", gap: 6,
                            padding: "4px 10px", borderRadius: 6,
                            background: "rgba(168,85,247,.08)", border: "1px solid rgba(168,85,247,.2)",
                            fontSize: 11, color: "#a855f7", fontFamily: "monospace", fontWeight: 500,
                          }}>
                            {pattern}
                            <button onClick={function() {
                              setConfig(function(prev) {
                                var next = JSON.parse(JSON.stringify(prev));
                                next.botUserAgents = next.botUserAgents.filter(function(p) { return p !== pattern; });
                                return next;
                              });
                            }} style={{ background: "none", border: "none", color: "#ef4444", cursor: "pointer", fontSize: 11, padding: 0 }}>{"\u2715"}</button>
                          </span>
                        );
                      })}
                    </div>
                    <div style={{ display: "flex", gap: 6 }}>
                      <input id="newUA" type="text" placeholder="Add pattern (e.g. headless)..." style={{
                        flex: 1, padding: "7px 12px", borderRadius: 8, border: "1px solid rgba(255,255,255,.08)",
                        background: "rgba(255,255,255,.03)", color: "#e2e8f0", fontSize: 12, fontFamily: "monospace", outline: "none",
                      }} onKeyDown={function(e) {
                        if (e.key === "Enter" && e.target.value.trim()) {
                          var val = e.target.value.trim();
                          setConfig(function(prev) {
                            var next = JSON.parse(JSON.stringify(prev));
                            if (next.botUserAgents.indexOf(val) === -1) next.botUserAgents.push(val);
                            return next;
                          });
                          e.target.value = "";
                        }
                      }} />
                      <button onClick={function() {
                        var input = document.getElementById("newUA");
                        if (input && input.value.trim()) {
                          var val = input.value.trim();
                          setConfig(function(prev) {
                            var next = JSON.parse(JSON.stringify(prev));
                            if (next.botUserAgents.indexOf(val) === -1) next.botUserAgents.push(val);
                            return next;
                          });
                          input.value = "";
                        }
                      }} style={{
                        padding: "7px 14px", borderRadius: 8, border: "none", cursor: "pointer",
                        background: "#a855f7", color: "#fff", fontSize: 11, fontWeight: 600,
                      }}>Add</button>
                    </div>
                  </div>

                  {/* Data URL */}
                  <div style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, padding: "22px 24px", border: "1px solid rgba(255,255,255,.04)" }}>
                    <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 10 }}>Data Source</div>
                    <input type="text" value={config.dataUrl}
                      onChange={function(e) {
                        var val = e.target.value;
                        setConfig(function(prev) { var next = JSON.parse(JSON.stringify(prev)); next.dataUrl = val; return next; });
                      }}
                      style={{
                        width: "100%", padding: "9px 12px", borderRadius: 8,
                        border: "1px solid rgba(255,255,255,.08)", background: "rgba(255,255,255,.03)",
                        color: "#e2e8f0", fontSize: 12, fontFamily: "monospace", outline: "none",
                      }} />
                  </div>
                </div>
              </div>

              {/* Reset + Run buttons */}
              <div style={{ display: "flex", justifyContent: "center", gap: 12, marginTop: 28 }}>
                <button onClick={function() { setConfig(JSON.parse(JSON.stringify(DEFAULT_CONFIG))); }} style={{
                  padding: "12px 28px", borderRadius: 12, border: "1px solid rgba(255,255,255,.08)",
                  background: "transparent", color: "#94a3b8", fontSize: 13, fontWeight: 600, cursor: "pointer",
                }}>Reset to Defaults</button>
                <button onClick={function() { setView("pipeline"); }} style={{
                  padding: "12px 28px", borderRadius: 12, border: "none",
                  background: "linear-gradient(135deg,#f43f5e,#e11d48)", color: "#fff",
                  fontSize: 13, fontWeight: 700, cursor: "pointer",
                  boxShadow: "0 4px 20px rgba(244,63,94,.25)",
                }}>{"\u25B6"} Go to Pipeline</button>
              </div>

              {/* Config JSON preview */}
              <div style={{ marginTop: 24, background: "rgba(255,255,255,.02)", borderRadius: 16, padding: "18px 22px", border: "1px solid rgba(255,255,255,.04)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: "#64748b" }}>Config JSON (exportable)</div>
                  <button onClick={function() { try { navigator.clipboard.writeText(JSON.stringify(config, null, 2)); } catch(e) {} }} style={{
                    padding: "4px 12px", borderRadius: 6, border: "none", cursor: "pointer",
                    background: "rgba(255,255,255,.06)", color: "#94a3b8", fontSize: 10, fontWeight: 600,
                  }}>Copy JSON</button>
                </div>
                <div style={{
                  fontFamily: "monospace", fontSize: 10, color: "#64748b", lineHeight: 1.7,
                  background: "#060a14", borderRadius: 8, padding: "12px 14px",
                  maxHeight: 200, overflowY: "auto", whiteSpace: "pre-wrap",
                }}>
                  {JSON.stringify(config, null, 2)}
                </div>
              </div>
            </div>
          )}

          {/* DASHBOARD */}
          {view === "dashboard" && stats && (
            <div style={{ animation: "fadeIn .4s" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: 12, marginBottom: 24 }}>
                <div>
                  <div style={{ fontSize: 10, color: "#475569", letterSpacing: 2.5, fontWeight: 700, marginBottom: 6 }}>PROOF OF VALUE \u2014 LIVE DATA</div>
                  <h2 style={{ fontSize: 28, fontWeight: 800, letterSpacing: -1.2, color: "#f1f5f9" }}>TechCorp \u2014 Threat Report</h2>
                  <div style={{ fontSize: 12, color: "#334155", marginTop: 4 }}>{stats.total} sessions analyzed from live endpoint \u00B7 ${stats?.cpc || 5} CPC</div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 14px", background: "rgba(16,185,129,.06)", borderRadius: 10, border: "1px solid rgba(16,185,129,.12)" }}>
                  <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#10b981" }} />
                  <span style={{ fontSize: 11, color: "#10b981", fontWeight: 600 }}>Processed from live data</span>
                </div>
              </div>

              {/* KPIs */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14, marginBottom: 20 }}>
                {[
                  { l: "SESSIONS", v: stats.total, c: "#6366f1", s: "from live endpoint" },
                  { l: "MONEY SAVED", v: stats.saved, p: "$", c: "#10b981", s: stats.botClicks + " clicks x $" + (stats?.cpc || 5) },
                  { l: "IPS BLOCKED", v: stats.blockedCount, c: "#ef4444", s: "written to blocklist" },
                  { l: "FORMS BLOCKED", v: stats.formsBlocked, c: "#f59e0b", s: "conversions protected" },
                ].map(function(kpi, i) {
                  return (
                    <div key={kpi.l} style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, padding: "22px 20px", border: "1px solid rgba(255,255,255,.04)" }}>
                      <div style={{ fontSize: 9, color: "#475569", letterSpacing: 1.5, fontWeight: 700, marginBottom: 10 }}>{kpi.l}</div>
                      <div style={{ fontSize: 34, fontWeight: 800, color: kpi.c, letterSpacing: -2 }}>
                        <AnimNum value={kpi.v} prefix={kpi.p} delay={i * 150} />
                      </div>
                      <div style={{ fontSize: 11, color: "#334155", marginTop: 5 }}>{kpi.s}</div>
                    </div>
                  );
                })}
              </div>

              {/* Sub-tabs */}
              <div style={{ display: "flex", gap: 3, marginBottom: 16, background: "rgba(255,255,255,.02)", borderRadius: 10, padding: 3, width: "fit-content" }}>
                {[["overview","Overview"],["map","Threat Map"],["tuning","Rule Tuning"],["sessions","Sessions"]].map(function(pair) {
                  return (
                    <button key={pair[0]} onClick={function() { setDashTab(pair[0]); }} style={{
                      padding: "6px 16px", borderRadius: 8, border: "none", cursor: "pointer", fontSize: 11, fontWeight: 600,
                      background: dashTab === pair[0] ? "rgba(255,255,255,.08)" : "transparent",
                      color: dashTab === pair[0] ? "#f1f5f9" : "#475569",
                    }}>{pair[1]}</button>
                  );
                })}
              </div>

              {/* OVERVIEW */}
              {dashTab === "overview" && (
                <div style={{ animation: "fadeIn .3s" }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
                    <div style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, padding: "20px 22px", border: "1px solid rgba(255,255,255,.04)" }}>
                      <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 16 }}>Traffic Breakdown</div>
                      <ResponsiveContainer width="100%" height={200}>
                        <PieChart><Pie data={pieData} dataKey="value" cx="50%" cy="50%" innerRadius={46} outerRadius={78} paddingAngle={4} strokeWidth={0}>
                          {pieData.map(function(e, i) { return <Cell key={i} fill={PIE_COLORS[i]} />; })}
                        </Pie><RTooltip contentStyle={ttStyle} /></PieChart>
                      </ResponsiveContainer>
                      <div style={{ display: "flex", justifyContent: "center", gap: 18, marginTop: 6 }}>
                        {pieData.map(function(d, i) {
                          return <div key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}><div style={{ width: 8, height: 8, borderRadius: 2, background: PIE_COLORS[i] }} /><span style={{ fontSize: 11, color: "#64748b" }}>{d.name} <b style={{ color: "#94a3b8" }}>{d.value}</b></span></div>;
                        })}
                      </div>
                    </div>
                    <div style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, padding: "20px 22px", border: "1px solid rgba(255,255,255,.04)" }}>
                      <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 16 }}>Detection Rules</div>
                      <ResponsiveContainer width="100%" height={220}>
                        <BarChart data={stats.flagCounts} layout="vertical"><XAxis type="number" tick={{ fill: "#475569", fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis type="category" dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} width={78} axisLine={false} tickLine={false} /><RTooltip contentStyle={ttStyle} /><Bar dataKey="count" radius={[0,6,6,0]} barSize={20}>{stats.flagCounts.map(function(d,i) { return <Cell key={i} fill={d.color} />; })}</Bar></BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                  {stats.timeline && stats.timeline.length > 0 && (
                    <div style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, padding: "20px 22px", border: "1px solid rgba(255,255,255,.04)" }}>
                      <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 14 }}>Traffic Timeline</div>
                      <ResponsiveContainer width="100%" height={140}>
                        <AreaChart data={stats.timeline}>
                          <XAxis dataKey="hour" tick={{ fill: "#475569", fontSize: 10 }} axisLine={false} tickLine={false} />
                          <YAxis tick={{ fill: "#475569", fontSize: 10 }} axisLine={false} tickLine={false} />
                          <RTooltip contentStyle={ttStyle} />
                          <Area type="monotone" dataKey="Valid" stackId="1" stroke="#10b981" fill="#10b98130" strokeWidth={2} />
                          <Area type="monotone" dataKey="Suspicious" stackId="1" stroke="#f59e0b" fill="#f59e0b30" strokeWidth={2} />
                          <Area type="monotone" dataKey="Bot" stackId="1" stroke="#ef4444" fill="#ef444430" strokeWidth={2} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  )}
                </div>
              )}

              {dashTab === "map" && <div style={{ animation: "fadeIn .3s" }}><WorldMap threats={stats.recentThreats} /></div>}

              {dashTab === "tuning" && (
                <div style={{ animation: "fadeIn .3s", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                  <RuleTuner sessions={sessions} />
                  <div style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, padding: "20px 22px", border: "1px solid rgba(255,255,255,.04)" }}>
                    <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8 }}>How It Works</div>
                    <div style={{ fontSize: 12, color: "#64748b", lineHeight: 1.8 }}>
                      <div style={{ marginBottom: 12 }}>Each session is scored by four rules. Scores stack \u2014 multiple triggers = higher score.</div>
                      <div style={{ marginBottom: 12 }}>Score &gt; <strong style={{ color: "#ef4444" }}>80</strong> = <strong style={{ color: "#ef4444" }}>Bot</strong> (blocked). Score 1\u201380 = <strong style={{ color: "#f59e0b" }}>Suspicious</strong>. Score 0 = <strong style={{ color: "#10b981" }}>Valid</strong>.</div>
                      <div style={{ marginBottom: 12 }}>The rule tuner recalculates against the <strong style={{ color: "#94a3b8" }}>real dataset</strong> you just fetched. Adjust sliders to see how threshold changes impact detection and ROI.</div>
                      <div>This is the kind of tuning a CSE does with enterprise clients to balance false positives vs. protection coverage.</div>
                    </div>
                  </div>
                </div>
              )}

              {dashTab === "sessions" && (
                <div style={{ animation: "fadeIn .3s" }}>
                  <div style={{ background: "rgba(255,255,255,.02)", borderRadius: 16, border: "1px solid rgba(255,255,255,.04)", overflow: "hidden" }}>
                    <div style={{ padding: "14px 22px 10px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
                      <div><span style={{ fontSize: 13, fontWeight: 700 }}>Session Log</span><span style={{ fontSize: 11, color: "#334155", marginLeft: 10 }}>{filteredSessions.length} sessions</span></div>
                      <div style={{ display: "flex", gap: 4 }}>
                        {["all","bot","suspicious","valid"].map(function(fk) {
                          var fc = fk === "bot" ? "#ef4444" : fk === "suspicious" ? "#f59e0b" : fk === "valid" ? "#10b981" : "#94a3b8";
                          return <button key={fk} onClick={function() { setFilter(fk); }} style={{ padding: "5px 14px", borderRadius: 6, border: "none", cursor: "pointer", fontSize: 11, fontWeight: 600, background: filter === fk ? fc + "18" : "rgba(255,255,255,.03)", color: filter === fk ? fc : "#475569" }}>{fk.charAt(0).toUpperCase() + fk.slice(1)}</button>;
                        })}
                      </div>
                    </div>
                    <div style={{ overflowX: "auto" }}>
                      <table style={{ width: "100%", borderCollapse: "collapse" }}>
                        <thead><tr style={{ borderTop: "1px solid rgba(255,255,255,.04)" }}>
                          {["IP","Risk","Verdict","Flags","Country","Page","Clicks","Saved",""].map(function(h) {
                            return <th key={h} style={{ padding: "9px 16px", textAlign: "left", fontSize: 9, fontWeight: 700, color: "#334155", letterSpacing: 1.2, textTransform: "uppercase", borderBottom: "1px solid rgba(255,255,255,.03)" }}>{h}</th>;
                          })}
                        </tr></thead>
                        <tbody>
                          {filteredSessions.slice(0, 50).map(function(s, i) {
                            var vc = getVC(s.verdict);
                            return (
                              <tr key={s.session_id || i} onClick={function() { setSelectedSession(s); }}
                                style={{ borderBottom: "1px solid rgba(255,255,255,.02)", cursor: "pointer", transition: "background .12s" }}
                                onMouseEnter={function(e) { e.currentTarget.style.background = "rgba(255,255,255,.025)"; }}
                                onMouseLeave={function(e) { e.currentTarget.style.background = "transparent"; }}>
                                <td style={{ padding: "10px 16px", fontFamily: "monospace", fontSize: 11.5, color: "#94a3b8" }}>{s.ip_address}</td>
                                <td style={{ padding: "10px 16px" }}>
                                  <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                                    <div style={{ width: 40, height: 4, borderRadius: 2, background: "rgba(255,255,255,.04)", overflow: "hidden" }}>
                                      <div style={{ width: s.risk_score + "%", height: "100%", background: vc, borderRadius: 2 }} />
                                    </div>
                                    <span style={{ fontSize: 10.5, fontWeight: 700, color: vc, fontFamily: "monospace" }}>{s.risk_score || "\u2014"}</span>
                                  </div>
                                </td>
                                <td style={{ padding: "10px 16px" }}><span style={{ fontSize: 9.5, fontWeight: 700, padding: "3px 10px", borderRadius: 20, background: vc + "12", color: vc }}>{s.verdict.toUpperCase()}</span></td>
                                <td style={{ padding: "10px 16px" }}>
                                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                    {(s.flags || []).map(function(f) { var info = FLAG_INFO[f]; if (!info) return null; return <span key={f} style={{ fontSize: 9, padding: "2px 7px", borderRadius: 4, background: info.color + "10", color: info.color, fontWeight: 600 }}>{info.label}</span>; })}
                                    {(!s.flags || s.flags.length === 0) && <span style={{ fontSize: 10, color: "#1e293b" }}>\u2014</span>}
                                  </div>
                                </td>
                                <td style={{ padding: "10px 16px", fontSize: 12, color: "#94a3b8" }}>{COUNTRY_EMOJI[s.country] || ""} {s.country}</td>
                                <td style={{ padding: "10px 16px", fontSize: 11.5, color: "#475569", fontFamily: "monospace" }}>{s.page_url}</td>
                                <td style={{ padding: "10px 16px", fontSize: 12, fontWeight: 600 }}>{s.clicks}</td>
                                <td style={{ padding: "10px 16px", fontSize: 12, fontWeight: 700, color: s.verdict === "Bot" ? "#10b981" : "#1e293b" }}>{s.verdict === "Bot" ? "$" + (s.clicks * (config?.cpc || 5)).toLocaleString() : "\u2014"}</td>
                                <td style={{ padding: "10px 16px", fontSize: 11, color: "#334155" }}>{"\u2192"}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                    {filteredSessions.length > 50 && <div style={{ padding: "10px 22px", borderTop: "1px solid rgba(255,255,255,.03)", fontSize: 11, color: "#475569", textAlign: "center" }}>Showing 50 of {filteredSessions.length} sessions</div>}
                    <div style={{ padding: "10px 22px", borderTop: "1px solid rgba(255,255,255,.03)", fontSize: 11, color: "#334155", textAlign: "center" }}>Click any row to investigate</div>
                  </div>
                </div>
              )}

              {/* ROI */}
              <div style={{ marginTop: 20, borderRadius: 16, padding: "26px 30px", background: "linear-gradient(135deg,rgba(16,185,129,.06),rgba(6,182,212,.04))", border: "1px solid rgba(16,185,129,.1)", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 20 }}>
                <div>
                  <div style={{ fontSize: 9, color: "#475569", letterSpacing: 2, fontWeight: 700, marginBottom: 6 }}>PROJECTED ANNUAL SAVINGS</div>
                  <div style={{ fontSize: 40, fontWeight: 800, color: "#10b981", letterSpacing: -2.5 }}>
                    <AnimNum value={Math.round(stats.saved * 365)} prefix="$" delay={300} />
                  </div>
                  <div style={{ fontSize: 11, color: "#334155", marginTop: 3 }}>Based on current sample detection rate</div>
                </div>
                <div style={{ display: "flex", gap: 32 }}>
                  {[
                    { l: "Bot", v: ((stats.bot / stats.total) * 100).toFixed(1) + "%", c: "#ef4444" },
                    { l: "Suspicious", v: ((stats.suspicious / stats.total) * 100).toFixed(1) + "%", c: "#f59e0b" },
                    { l: "Clean", v: ((stats.valid / stats.total) * 100).toFixed(1) + "%", c: "#10b981" },
                  ].map(function(item) {
                    return <div key={item.l} style={{ textAlign: "center" }}><div style={{ fontSize: 24, fontWeight: 800, color: item.c, letterSpacing: -1 }}>{item.v}</div><div style={{ fontSize: 10, color: "#475569", marginTop: 2 }}>{item.l}</div></div>;
                  })}
                </div>
              </div>
            </div>
          )}

          {/* EMAIL */}
          {view === "email" && stats && (
            <div style={{ animation: "fadeIn .4s", maxWidth: 700, margin: "0 auto" }}>
              <div style={{ marginBottom: 24 }}>
                <div style={{ fontSize: 10, color: "#475569", letterSpacing: 2.5, fontWeight: 700, marginBottom: 6 }}>DELIVERABLE</div>
                <h2 style={{ fontSize: 28, fontWeight: 800, letterSpacing: -1, color: "#f1f5f9" }}>Customer Email</h2>
                <div style={{ fontSize: 12, color: "#334155", marginTop: 4 }}>Auto-generated from real pipeline results</div>
              </div>
              <EmailPreview stats={stats} />
            </div>
          )}
        </div>

        <ThreatModal session={selectedSession} onClose={function() { setSelectedSession(null); }} />
      </div>
    </div>
  );
}