import { ShieldCheck, Activity } from "lucide-react";
export default function Header({ health }) {
  return <header className="topbar"><div className="brand"><div className="brand-mark"><ShieldCheck size={23}/></div><div><div className="brand-name">MCP <span>WARDEN</span></div><div className="brand-tag">DECLARED INTENT → OBSERVED BEHAVIOR → SECURITY DECISION</div></div></div><div className="status"><span className="pulse"/><span>{health ? "API CONNECTED" : "CONNECTING"}</span><Activity size={15}/></div></header>;
}
