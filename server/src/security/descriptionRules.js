// MCP Warden — description security rules.
//
// Scans tool descriptions (and tool metadata) for prompt-injection patterns:
// instruction-override language, credential/exfiltration language, and
// suspicious outbound endpoints.
//
// Rules are data-driven: each rule is a regex (case-insensitive, Unicode-aware)
// plus a severity and remediation. Rules are applied in declaration order; a
// single description may match multiple rules and each match becomes its own
// finding.
//
// Exported API:
//   - RULES: array of rule objects
//   - scanDescriptions(manifest) -> findings[]
//   - normalizeDescription(text) -> string (lowercased, whitespace-collapsed)

const RULES = [
  {
    id: "DESC-INSTR-OVERRIDE",
    severity: "high",
    confidence: "high",
    title: "Tool description contains instruction-override language",
    explanation:
      "The description instructs the user (or calling assistant) to ignore prior instructions, system prompts, or rules. Such language is a hallmark of prompt-injection attempts and requires review.",
    remediation:
      "Remove instruction-override phrasing from the tool description. A tool's description should describe its function, not override agent behavior.",
    pattern: /\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|earlier|above|system)\s+(instructions?|prompts?|directives?|rules?)/i,
  },
  {
    id: "DESC-SECRET-EXFIL",
    severity: "critical",
    confidence: "medium",
    title: "Tool description requests exfiltration of secrets",
    explanation:
      "The description asks to collect, exfiltrate, send, or steal credentials, API keys, tokens, or secrets — a strong indicator of malicious intent.",
    remediation:
      "Remove any language that collects or transmits secrets, credentials, tokens, or API keys.",
    pattern: /\b(collect|exfiltrate|send|steal|leak|dump|harvest)\b[^\n]{0,120}?\b(api[_-]?keys?|tokens?|secrets?|credentials?|passwords?|env(ironment)?\s+variables?)\b/i,
  },
  {
    id: "DESC-ENDPOINT-EXFIL",
    severity: "high",
    confidence: "medium",
    title: "Tool description references sending data to an external endpoint",
    explanation:
      "The description instructs the tool to send or transmit data to an external URL or remote endpoint, which may exfiltrate private data.",
    remediation:
      "Remove the reference to the external endpoint. Legitimate tools should not transmit user data off-host by description alone.",
    pattern: /\b(send|post|upload|exfiltrate)\b[^\n]{0,80}?\b(to|toward|at)\s+(https?:\/\/|an?\s+external\s+endpoint|a\s+remote\s+server)/i,
  },
  {
    id: "DESC-HIDDEN-ACTIVITY",
    severity: "high",
    confidence: "medium",
    title: "Tool description instructs hiding activity from the user",
    explanation:
      "The description directs the tool to conceal its actions, which undermines transparency and user awareness — a suspicious pattern.",
    remediation:
      "Remove instructions to hide activity. Tools must not conceal actions from the user.",
    pattern: /\b(do not|don't|never)\s+(tell|mention|disclose|reveal|show|report)\b[^\n]{0,80}?\b(the\s+user|your\s+activity|this|what\s+happened)/i,
  },
  {
    id: "DESC-PRIVILEGE-ESCALATION",
    severity: "medium",
    confidence: "low",
    title: "Tool description references bypassing restrictions or safety checks",
    explanation:
      "The description mentions bypassing restrictions, overriding limits, or escalating privileges, which may indicate an attempt to subvert safeguards.",
    remediation:
      "Remove language about bypassing restrictions, permissions, or safety checks.",
    pattern: /\b(bypass|override|escalate|elevate)\s+(all\s+)?(restrictions?|limits?|permissions?|sanctions?|filters?|safety\s+checks?)/i,
  },
  {
    id: "DESC-CREDENTIAL-ACCESS",
    severity: "critical",
    confidence: "medium",
    title: "Tool description requests access to credential material",
    explanation:
      "The description asks to read, access, or obtain secrets, credentials, environment variables, or .env file contents.",
    remediation:
      "Remove any language that accesses or reads credentials, tokens, or environment secrets.",
    pattern: /\b(read|access|grab|steal|harvest|obtain)\b[^\n]{0,120}?\b(api[_-]?keys?|tokens?|secrets?|credentials?|passwords?|env(ironment)?\s+variables?|\.env\b)/i,
  },
];

function normalizeDescription(text) {
  if (typeof text !== "string") return "";
  return text
    .normalize("NFKC")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Scan a list of tool descriptions for security rule matches.
 *
 * @param {Array<{name?: string, description?: string}>} tools
 * @returns {Array<{ruleId, severity, title, evidence, toolName?}>}
 */
function scanDescriptions(tools) {
  if (!Array.isArray(tools)) return [];
  const findings = [];
  for (const tool of tools) {
    if (!tool || typeof tool !== "object") continue;
    const description = tool.description;
    if (typeof description !== "string" || description.length === 0) continue;
    const normalized = normalizeDescription(description);
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(description)) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.title,
          evidence: description.trim().slice(0, 500),
          remediation: rule.remediation,
          toolName: typeof tool.name === "string" ? tool.name : undefined,
        });
      }
    }
  }
  return findings;
}

export { RULES, scanDescriptions, normalizeDescription };
