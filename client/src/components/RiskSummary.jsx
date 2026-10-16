import { ShieldAlert, ScanSearch, Fingerprint, GitCompareArrows } from "lucide-react";
export default function RiskSummary({ result, comparison }) {
  const score = result?.score;
  const drift = comparison?.drift;
  const cards = [
    { label: "HEURISTIC RISK", value: score ? `${score.total}/100` : "—", note: score?.category || "Awaiting scan", icon: ShieldAlert, tone: score?.category?.toLowerCase() || "" },
    { label: "FINDINGS", value: result ? result.findings.length : "—", note: "Description + source indicators", icon: ScanSearch },
    { label: "FINGERPRINT", value: result ? `${result.fingerprint.slice(0, 12)}…` : "—", note: "SHA-256 metadata digest", icon: Fingerprint, mono: true },
    { label: "METADATA DRIFT", value: drift ? drift.status.toUpperCase() : "—", note: drift ? `${drift.added.length} added · ${drift.removed.length} removed · ${drift.modified.length} modified` : "Compare with a baseline", icon: GitCompareArrows }
  ];
  return <div className="summary-grid">{cards.map(({ label, value, note, icon: Icon, tone, mono }) => <article className="metric-card" key={label}><div className="metric-top"><span>{label}</span><Icon size={17}/></div><div className={`metric-value ${tone} ${mono ? "mono" : ""}`}>{value}</div><div className="metric-note">{note}</div></article>)}</div>;
}
