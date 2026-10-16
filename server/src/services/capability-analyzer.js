const CAPABILITY_RULES = [
  {
    key: "filesystem",
    declaredPattern: /\b(?:file\s*system|files?|directories?|folders?)\b/i,
    sourceRuleIds: new Set(["SRC005", "SRC008"]),
  },
  {
    key: "processExecution",
    declaredPattern: /\b(?:shell|commands?|process(?:es)?|spawn|execute)\b/i,
    sourceRuleIds: new Set(["SRC002"]),
  },
  {
    key: "network",
    declaredPattern: /\b(?:network|https?|internet|webhooks?|endpoints?|requests?|fetch)\b/i,
    sourceRuleIds: new Set(["SRC006", "SRC007"]),
  },
  {
    key: "environmentVariables",
    declaredPattern: /\b(?:environment\s+variables?|process\.env|\.env\s+files?|credentials?|secrets?|api\s+keys?|tokens?)\b/i,
    sourceRuleIds: new Set(["SRC006", "SRC009"]),
  },
  {
    key: "dynamicCode",
    declaredPattern: /\b(?:eval|dynamic\s+code|arbitrary\s+code|execute\s+code|new\s+function)\b/i,
    sourceRuleIds: new Set(["SRC001"]),
  },
];

/**
 * Summarize capability signals without treating metadata claims as verified behavior.
 * @param {object[]} tools
 * @param {object[]} sourceFindings
 * @returns {object}
 */
export function analyzeCapabilities(tools = [], sourceFindings = []) {
  const toolList = Array.isArray(tools) ? tools : [];
  const findings = Array.isArray(sourceFindings) ? sourceFindings : [];
  const capabilities = {};

  for (const rule of CAPABILITY_RULES) {
    const declared = [];
    for (const tool of toolList) {
      if (!tool || typeof tool !== "object") continue;
      let schema = "";
      try {
        schema = JSON.stringify(tool.inputSchema ?? "");
      } catch {
        schema = "";
      }
      const metadata = `${tool.name ?? ""}\n${tool.description ?? ""}\n${schema}`;
      const match = rule.declaredPattern.exec(metadata);
      if (match) {
        declared.push({
          toolName: typeof tool.name === "string" ? tool.name : undefined,
          source: "tool_metadata",
          evidence: match[0].slice(0, 160),
        });
      }
    }

    const staticallyObserved = findings
      .filter((finding) => rule.sourceRuleIds.has(finding.ruleId ?? finding.id))
      .map((finding) => ({
        ruleId: finding.ruleId ?? finding.id,
        file: finding.file,
        line: finding.line,
        evidence: finding.evidence,
      }));

    capabilities[rule.key] = {
      declared,
      staticallyObserved,
      dynamicallyObserved: [],
      unknown: true,
    };
  }

  return {
    analysisType: "static",
    runtimeAnalysisPerformed: false,
    capabilities,
    limitations: [
      "Declared capabilities are inferred from untrusted tool metadata and are not proof of runtime behavior.",
      "No source code or MCP server was executed; dynamic behavior remains unknown.",
    ],
  };
}