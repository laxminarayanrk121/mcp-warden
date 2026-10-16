// MCP Warden — demo script.
//
// Exercises the full backend workflow using the three fixture scenarios:
//   - benign:   low-risk, expected to score ~0
//   - suspicious: contains a clearly malicious description, expected to score >0
//   - rug-pull: shows how a baseline can detect description changes and added tools.
//
// The script:
//   1. Starts the MCP Warden API in a child process.
//   2. Calls each fixture through the POST /api/scan endpoint.
//   3. For rug-pull, it also creates a baseline from baseline.json and
//      compares it against current.json to show drift detection.
//   4. Prints findings, fingerprints, and scores in a human-readable format.
//   5. Shuts down the API child process.
//
// Run with: node scripts/demo.js
// Requires: the API must be buildable (npm run install:server) and the
//           http-shim.js must be present (it is).

import { spawn } from "node:child_process";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

const API_PORT = 4000;
const API_BASE = `http://localhost:${API_PORT}`;

// Helper: perform an HTTP request and return parsed JSON.
async function fetchJSON(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: options.method ?? "GET",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `HTTP ${response.status}: ${response.statusText}\n${errorBody}`
    );
  }
  return response.json();
}

// Start the API server as a child process.
function startApiServer() {
  console.log("🚀 Starting MCP Warden API...");
  const api = spawn("node", ["--watch", "src/index.js"], {
    cwd: join(process.cwd(), "server"),
    stdio: ["ignore", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  api.stdout.on("data", (data) => {
    stdout += data;
    process.stdout.write(data);
  });
  api.stderr.on("data", (data) => {
    stderr += data;
    process.stderr.write(data);
  });

  // Wait until we hear the "running on" line or timeout after 10s.
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      api.kill();
      reject(
        new Error(
          `API did not start within 10 seconds.\\nstdout:\\n${stdout}\\nstderr:\\n${stderr}`
        )
      );
    }, 10_000);

    api.stdout.on("data", (data) => {
      if (data.includes("MCP Warden API running on")) {
        clearTimeout(timeout);
        resolve(api);
      }
    });
  });
}

// Stop the API child process.
function stopApiServer(api) {
  if (!api) return;
  console.log("\\n🛑 Stopping MCP Warden API...");
  api.kill();
}

// Demo: benign fixture.
async function demoBenign() {
  console.log("\\n📋 DEMO: Benign fixture");
  console.log("   Expected: low risk, no findings.");
  const res = await fetchJSON("/api/scan", {
    method: "POST",
    body: { fixtureId: "benign", includeSourceScan: false },
  });
  console.log(
    `   🎯 Score: ${res.score}/100 → ${res.riskLevel} (baseline: ${res.baselineStatus})`
  );
  console.log(`   🔐 Fingerprint: ${res.fingerprint}`);
  console.log(`   🐛 Findings: ${res.findings.length}`);
  for (const f of res.findings) {
    console.log(`      - [${f.severity}] ${f.title}`);
  }
  return res;
}

// Demo: suspicious fixture.
async function demoSuspicious() {
  console.log("\\n📋 DEMO: Suspicious fixture");
  console.log("   Expected: high risk due to description findings.");
  const res = await fetchJSON("/api/scan", {
    method: "POST",
    body: { fixtureId: "suspicious", includeSourceScan: false },
  });
  console.log(
    `   🎯 Score: ${res.score}/100 → ${res.riskLevel} (baseline: ${res.baselineStatus})`
  );
  console.log(`   🔐 Fingerprint: ${res.fingerprint}`);
  console.log(`   🐛 Findings: ${res.findings.length}`);
  for (const f of res.findings) {
    console.log(`      - [${f.severity}] ${f.title}`);
    console.log(`          Evidence: "${f.evidence.slice(0, 80)}..."`);
  }
  return res;
}

// Demo: rug-pull scenario (baseline + drift detection).
async function demoRugPull() {
  console.log("\\n📋 DEMO: Rug-pull scenario (baseline + drift)");
  console.log(
    "   Step 1: Create a baseline from fixtures/rug-pull/baseline.json"
  );
  let baselineRes;
  try {
    baselineRes = await fetchJSON("/api/baselines", {
      method: "POST",
      body: { fixtureId: "rug-pull", name: "rug-pull-baseline" },
    });
  } catch (err) {
    // If the baseline already exists, just list and pick the first.
    const list = await fetchJSON("/api/baselines");
    if (list.success && list.baselines && list.baselines.length > 0) {
      baselineRes = {
        success: true,
        baseline: list.baselines[0],
      };
    } else {
      throw err;
    }
  }
  const baselineId = baselineRes.baseline.id;
  console.log(`   ✅ Baseline created: ${baselineId}`);

  console.log(
    "   Step 2: Scan fixtures/rug-pull/current.json (changed description + added tool)"
  );
  const scanRes = await fetchJSON("/api/scan", {
    method: "POST",
    body: {
      fixtureId: "rug-pull",
      includeSourceScan: false,
      baselineId,
    },
  });
  console.log(
    `   🎯 Score: ${scanRes.score}/100 → ${scanRes.riskLevel} (baseline: ${scanRes.baselineStatus})`
  );
  console.log(`   🔐 Fingerprint: ${scanRes.fingerprint}`);
  console.log(`   🐛 Findings: ${scanRes.findings.length}`);
  for (const f of scanRes.findings) {
    console.log(`      - [${f.severity}] ${f.title}`);
  }

  if (scanRes.metadataChanges) {
    const { added, removed, modified } = scanRes.metadataChanges;
    if (added.length) {
      console.log(`   ➕ Added tools (${added.length}):`);
      for (const t of added) {
        console.log(`      - ${t.name}: ${t.description.slice(0, 60)}...`);
      }
    }
    if (removed.length) {
      console.log(`   ➖ Removed tools (${removed.length}):`);
      for (const t of removed) {
        console.log(`      - ${t.name}`);
      }
    }
    if (modified.length) {
      console.log(`   ✏️  Modified tools (${modified.length}):`);
      for (const m of modified) {
        console.log(`      - ${m.name}`);
        for (const c of m.changes) {
          console.log(`          ${c.field}: "${c.before.slice(0, 40)}..." → "${c.after.slice(
            0,
            40
          )}..."`);
        }
      }
    }
  }

  console.log(
    `   📝 Limitations: ${scanRes.limitations
      .map((l) => `   - ${l}`)
      .join("\\n")}`
  );

  return { baselineId, scanRes };
}

// Demo: report retrieval.
async function demoReports(scanId) {
  console.log("\\n📋 DEMO: Report retrieval");
  console.log(`   Fetching report for scanId: ${scanId}`);
  const jsonReport = await fetchJSON(`/api/reports/${scanId}`);
  console.log(
    `   📄 JSON report keys: ${Object.keys(jsonReport)
      .filter((k) => k !== "findings" && k !== "metadataChanges")
      .join(", ")}`
  );
  console.log(`   📄 Findings in report: ${jsonReport.report?.findings?.length ?? 0}`);

  const mdReportRes = await fetch(`${API_BASE}/api/reports/${scanId}/md`);
  const mdReport = await mdReportRes.text();
  console.log(`   📄 Markdown report length: ${mdReport.length} characters`);
  console.log(
     `   📄 Markdown preview:\\n${mdReport
      .split("\\n")
      .slice(0, 12)
      .join("\\n")}`
  );
}

// Orchestrator.
async function runDemo() {
  let api;
  try {
    api = await startApiServer();

    // Give the server an extra moment to settle.
    await new Promise((r) => setTimeout(r, 1500));

    const benignRes = await demoBenign();
    const suspiciousRes = await demoSuspicious();
    const { baselineId, scanRes: rugPullRes } = await demoRugPull();

    // Show that we can fetch a report by scanId.
    await demoReports(rugPullRes.scanId);

    console.log("\\n🎉 All demos completed successfully.");
    console.log("   Summary:");
    console.log(`   - Benign:   ${benignRes.score}/100 (${benignRes.riskLevel})`);
    console.log(`   - Suspicious: ${suspiciousRes.score}/100 (${suspiciousRes.riskLevel})`);
    console.log(`   - Rug-pull (current vs baseline): ${rugPullRes.score}/100 (${rugPullRes.riskLevel})`);
  } catch (err) {
    console.error("\\n❌ Demo failed:", err);
    process.exit(1);
  } finally {
    stopApiServer(api);
  }
}

// If this file is run directly, execute the demo.
if (import.meta.url === `file://${process.argv[1]}`) {
  runDemo().catch((err) => {
    console.error("� Demo failed:", err);
    process.exit(1);
  });
}
