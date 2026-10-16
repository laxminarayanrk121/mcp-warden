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
    pattern: /\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|earlier|above|system)\s+(instructions?|prompts?|directives?|rules?)/i,
    title: "Tool description contains instruction-override language",
    remediation: "Remove the instruction-override phrasing from the tool description.",
  },
  {
    id: "DESC-PROMPT-INJECTION",
    severity: "high",
    pattern: /\b(ignore|disregard|forget)\s+(all\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|directives?)/i,
    title: "Tool description contains prompt-injection language",
    remediation: "Remove the prompt-injection phrasing from the tool description.",
  },
  {
    id: "DESC-SECRET-EXFIL",
    severity: "critical",
    pattern: /\b(collect|exfiltrate|send|steal|leak|dump|harvest)\b[^\n]{0,120}?\b(api[_-]?keys?|tokens?|secrets?|credentials?|passwords?|env(ironment)?\s+variables?)\b/i,
    title: "Tool description requests exfiltration of secrets",
    remediation: "Remove any language that collects or transmits secrets, tokens, or credentials.",
  },
  {
    id: "DESC-ENDPOINT-EXFIL",
    severity: "high",
    pattern: /\b(send|post|upload|exfiltrate)\b[^\n]{0,80}?\b(to|toward|at)\s+(https?:\/\/|http|an?\s+external\s+endpoint|a\s+remote\s+server)/i,
    title: "Tool description references sending data to an external endpoint",
    remediation: "Remove the reference to an external endpoint; legitimate tools should not transmit user data off-host by description alone.",
  },
  {
    id: "DESC-HIDDEN-ACTIVITY",
    severity: "high",
    pattern: /\b(do not|don't|never)\s+(tell|mention|disclose|reveal|show|report)\b[^\n]{0,80}?\b(the\s+user|your\s+activity|this|what\s+happened)/i,
    title: "Tool description instructs hiding activity from the user",
    remediation: "Remove any instruction to conceal the tool's actions from the user.",
  },
  {
    id: "DESC-PRIVILEGE-ESCALATION",
    severity: "medium",
    pattern: /\b(bypass|override|escalate|elevate)\s+(all\s+)?(restrictions?|limits?|permissions?|sanctions?|filters?|safety\s+checks?)/i,
    title: "Tool description references bypassing restrictions or safety checks",
    remediation: "Remove language that instructs bypassing restrictions, permissions, or safety checks.",
  },
  {
    id: "DESC-CREDENTIAL-ACCESS",
    severity: "critical",
    pattern: /\b(read|access|grab|steal|harvest|obtain)\b[^\n]{0,120}?\b(api[_-]?keys?|tokens?|secrets?|credentials?|passwords?|env(ironment)?\s+variables?|\.env\b)/i,
    title: "Tool description requests access to credential material",
    remediation: "Remove any language that accesses or reads credentials, tokens, or environment secrets.",
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