import { ChevronDown, ChevronUp, AlertTriangle } from "lucide-react";
import { useState } from "react";
export default function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);
  return <article className={`finding ${finding.severity}`}><button className="finding-trigger" onClick={() => setOpen(!open)}><span className="severity-icon"><AlertTriangle size={17}/></span><span className="finding-main"><span className="finding-title">{finding.category}</span><span className="finding-meta"><code>{finding.ruleId}</code> · {finding.toolName || finding.file || "Metadata"}{finding.line ? `:${finding.line}` : ""}</span></span><span className={`severity-label ${finding.severity}`}>{finding.severity}</span>{open ? <ChevronUp size={17}/> : <ChevronDown size={17}/>}</button>{open && <div className="finding-detail"><div className="detail-label">MATCHED EVIDENCE</div><pre>{finding.evidence}</pre><p>{finding.explanation}</p><div className="detail-label">RECOMMENDED REMEDIATION</div><p>{finding.remediation}</p></div>}</article>;
}
