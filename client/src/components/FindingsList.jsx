import { ScanSearch } from "lucide-react";
import FindingCard from "./FindingCard.jsx";
export default function FindingsList({ findings = [] }) {
  return <section className="panel"><div className="panel-heading"><div><div className="eyebrow">EVIDENCE REVIEW</div><h2>Security findings <span className="count">{findings.length}</span></h2></div><ScanSearch size={19}/></div>{findings.length ? <div className="finding-list">{findings.map((f, i) => <FindingCard key={`${f.id}-${i}`} finding={f}/>)}</div> : <div className="empty-state"><ScanSearch size={26}/><strong>No findings to display</strong><span>Run a scan to inspect the selected fixture.</span></div>}</section>;
}
