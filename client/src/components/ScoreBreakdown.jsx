import { BarChart3 } from "lucide-react";
const categories = [
  ["descriptionRisk", "Suspicious descriptions", 25],
  ["sourceRisk", "Source-code patterns", 20],
  ["metadataDriftRisk", "Metadata drift", 30],
  ["toolMismatchRisk", "Tool-set mismatch", 25]
];
export default function ScoreBreakdown({ score }) {
  return <section className="panel"><div className="panel-heading"><div><div className="eyebrow">EXPLAINABLE HEURISTICS</div><h2>Risk breakdown</h2></div><BarChart3 size={19}/></div>{score ? <><div className="score-total"><strong>{score.total}</strong><span>/ 100</span><b className={`severity-label ${score.category.toLowerCase()}`}>{score.category} risk</b></div><div className="score-bars">{categories.map(([key, label, max]) => <div className="score-row" key={key}><div><span>{label}</span><code>{score.breakdown[key]} / {max}</code></div><div className="bar"><span style={{ width: `${Math.min(100, score.breakdown[key] / max * 100)}%` }}/></div></div>)}</div>{score.notes?.map(n => <p className="muted-note" key={n}>{n}</p>)}</> : <div className="empty-state compact">Scores appear after a scan.</div>}<p className="disclaimer">Heuristic score only. It is not a probability of maliciousness.</p></section>;
}
