import { useEffect, useState } from "react";
import Header from "../components/Header.jsx";
import RiskSummary from "../components/RiskSummary.jsx";
import ScanControls from "../components/ScanControls.jsx";
import FindingsList from "../components/FindingsList.jsx";
import FingerprintPanel from "../components/FingerprintPanel.jsx";
import DriftDiff from "../components/DriftDiff.jsx";
import ScoreBreakdown from "../components/ScoreBreakdown.jsx";
import { getHealth, getFixtures, getBaselines, scanFixture, saveBaseline, compareFixture } from "../api/warden.api.js";
import { downloadReport } from "../utils/downloadReport.js";
import { ShieldCheck, LockKeyhole, AlertCircle } from "lucide-react";

export default function Dashboard() {
  const [health, setHealth] = useState(false);
  const [fixtures, setFixtures] = useState([]);
  const [fixture, setFixture] = useState("benign");
  const [baselines, setBaselines] = useState([]);
  const [baselineId, setBaselineId] = useState("");
  const [result, setResult] = useState(null);
  const [comparison, setComparison] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  useEffect(() => {
    Promise.all([getHealth(), getFixtures(), getBaselines()]).then(([h, f, b]) => {
      setHealth(h.status === "ok"); setFixtures(f.fixtures); setBaselines(b.baselines);
    }).catch(e => setError(`Backend connection failed: ${e.message}. Start the server on port 4000.`));
  }, []);
  async function perform(fn, successMessage) {
    setBusy(true); setError(""); setNotice("");
    try { await fn(); if (successMessage) setNotice(successMessage); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }
  const onScan = () => perform(async () => { setResult(await scanFixture(fixture)); setComparison(null); }, "Scan completed. Findings and score came from the backend.");
  const onSave = () => perform(async () => {
    const response = await saveBaseline(fixture);
    const next = await getBaselines(); setBaselines(next.baselines); setBaselineId(response.baseline.id);
    setNotice(`Baseline saved: ${response.baseline.fingerprint.slice(0, 16)}…`);
  });
  const onCompare = () => perform(async () => {
    const response = await compareFixture(baselineId, fixture); setComparison(response);
    if (result) setResult({ ...result, score: response.score });
  }, "Comparison completed.");
  const onExport = result ? () => downloadReport(buildReport(result, comparison), `mcp-warden-${fixture}-report.md`) : undefined;
  return <div className="app-shell"><Header health={health}/><main className="dashboard"><section className="page-intro"><div><div className="eyebrow"><span className="tiny-dot"/> SECURITY POSTURE / LOCAL ANALYSIS</div><h1>Tool Trust <span>Ledger.</span></h1><p>Inspect declared intent. Verify approved metadata. Surface suspicious changes with evidence.</p></div><div className="intro-chip"><LockKeyhole size={15}/> BASELINE INTEGRITY <b>{baselineId ? "BASELINE SELECTED" : "NOT SELECTED"}</b></div></section>
    <div className="fixture-banner"><ShieldCheck size={16}/><span><strong>SIMULATED ENVIRONMENT</strong> — Results use local fixtures and do not represent live MCP server observations.</span></div>
    {error && <div className="message error"><AlertCircle size={17}/>{error}</div>}{notice && <div className="message success"><ShieldCheck size={17}/>{notice}</div>}
    <RiskSummary result={result} comparison={comparison}/>
    <ScanControls fixture={fixture} setFixture={v => {setFixture(v); setComparison(null);}} fixtures={fixtures} baselines={baselines} baselineId={baselineId} setBaselineId={setBaselineId} onScan={onScan} onSave={onSave} onCompare={onCompare} onExport={onExport} busy={busy}/>
    <div className="content-grid"><div className="stack"><FindingsList findings={result?.findings || []}/><DriftDiff drift={comparison?.drift}/></div><div className="stack"><FingerprintPanel result={result} comparison={comparison}/><ScoreBreakdown score={result?.score}/></div></div>
    <footer><span>WARDEN CORE <b>v1.0.0</b></span><span>DECISION SUPPORT · NOT A SAFETY GUARANTEE</span></footer>
  </main></div>;
}
function buildReport(result, comparison) {
  const score = result.score;
  const lines = ["# MCP Warden Security Report", "", `- Scan ID: ${result.scanId}`, `- Timestamp: ${result.timestamp}`, `- Source: ${result.source}`, "- Result type: Controlled fixture demonstration", `- Current SHA-256: ${result.fingerprint}`, `- Risk score: ${score.total}/100 (${score.category})`, "", "## Score breakdown", ...Object.entries(score.breakdown).map(([k,v]) => `- ${k}: ${v}`), "", "## Findings", ""];
  if (!result.findings.length) lines.push("No configured rules matched.", "");
  for (const f of result.findings) lines.push(`### ${f.ruleId} — ${f.category}`, `- Severity: ${f.severity}`, `- Tool: ${f.toolName || "N/A"}`, `- Evidence: ${f.evidence}`, `- Explanation: ${f.explanation}`, `- Remediation: ${f.remediation}`, "");
  if (comparison?.drift) {
    const d = comparison.drift;
    lines.push("## Metadata drift", `- Status: ${d.status}`, `- Baseline SHA-256: ${d.baselineFingerprint}`, `- Current SHA-256: ${d.currentFingerprint}`, `- Added: ${d.added.map(x=>x.name).join(", ") || "None"}`, `- Removed: ${d.removed.map(x=>x.name).join(", ") || "None"}`, `- Modified: ${d.modified.map(x=>x.name).join(", ") || "None"}`, "");
    for (const t of d.modified) for (const c of t.changes) lines.push(`- ${t.name}.${c.field}: ${JSON.stringify(c.before)} → ${JSON.stringify(c.after)}`);
  }
  lines.push("", "## Limitations", "- Rules are heuristic and may produce false positives or miss threats.", "- A matching metadata hash does not prove runtime safety.", "- Fixture results are simulations, not live server observations.", "- Runtime monitoring and full semantic analysis are not implemented.");
  return lines.join("\n");
}
