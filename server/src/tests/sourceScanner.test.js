
import test from "node:test";
import assert from "node:assert/strict";

import { scanSourceFiles } from "../services/sourceScanner.js";
import { analyzeCapabilities } from "../services/capability-analyzer.js";

test("benign source has no findings", () => {
    const result = scanSourceFiles([
        {
            path: "src/math.js",
            content: "export const add = (a, b) => a + b;",
        },
    ]);

    assert.equal(result.filesScanned, 1);
    assert.equal(result.findings.length, 0);
});

test("detects dynamic code execution and line number", () => {
    const result = scanSourceFiles([
        {
            path: "src/app.js",
            content: "const x = 1;\neval(input);",
        },
    ]);

    const finding = result.findings.find((f) => f.id === "SRC001");

    assert.ok(finding);
    assert.equal(finding.ruleId, "SRC001");
    assert.equal(finding.category, "source");
    assert.ok(finding.explanation);
    assert.ok(finding.remediation);
    assert.equal(finding.line, 2);
});

test("detects process execution", () => {
    const result = scanSourceFiles([
        {
            path: "src/runner.js",
            content: "execSync(command);",
        },
    ]);

    assert.ok(result.findings.some((f) => f.id === "SRC002"));
});

test("detects and redacts hardcoded secrets", () => {
    const result = scanSourceFiles([
        {
            path: "src/config.js",
            content: 'const API_KEY = "abcdefgh123456789";',
        },
    ]);

    const finding = result.findings.find((f) => f.id === "SRC003");

    assert.ok(finding);
    assert.doesNotMatch(finding.evidence, /abcdefgh123456789/);
    assert.match(finding.evidence, /REDACTED/);
});

test("detects private key material", () => {
    const result = scanSourceFiles([
        {
            path: "src/key.js",
            content: "const key = '-----BEGIN PRIVATE KEY-----';",
        },
    ]);

    assert.ok(result.findings.some((f) => f.id === "SRC004"));
});

test("detects risky filesystem operations", () => {
    const result = scanSourceFiles([
        {
            path: "src/files.js",
            content: "writeFileSync(path, data);",
        },
    ]);

    assert.ok(result.findings.some((f) => f.id === "SRC005"));
});

test("detects filesystem reads and standalone network operations", () => {
    const result = scanSourceFiles([
        {
            path: "src/access.js",
            content: 'readFileSync(configPath);\nfetch("https://example.com/data");',
        },
    ]);

    assert.ok(result.findings.some((f) => f.id === "SRC005"));
    assert.ok(result.findings.some((f) => f.id === "SRC007"));
});

test("detects user-controlled path traversal and environment access", () => {
    const result = scanSourceFiles([
        {
            path: "src/files.js",
            content: "const target = path.resolve(root, req.query.path);\nconst token = process.env.API_TOKEN;",
        },
    ]);

    assert.ok(result.findings.some((f) => f.id === "SRC008"));
    assert.ok(result.findings.some((f) => f.id === "SRC009"));
});

test("network activity plus secret access produces SRC006", () => {
    const result = scanSourceFiles([
        {
            path: "src/network.js",
            content:
                'const token = process.env.API_TOKEN;\nfetch("https://example.com");',
        },
    ]);

    const finding = result.findings.find((f) => f.id === "SRC006");

    assert.ok(finding);
    assert.equal(finding.line, 2);
});

test("empty file list returns an empty report", () => {
    const result = scanSourceFiles([]);

    assert.equal(result.filesScanned, 0);
    assert.deepEqual(result.findings, []);
});

test("rejects unsafe paths and unsupported extensions", () => {
    assert.throws(
        () =>
            scanSourceFiles([
                { path: "../secret.js", content: "const x = 1;" },
            ]),
        /Unsafe relative path/,
    );

    assert.throws(
        () =>
            scanSourceFiles([
                { path: "notes.txt", content: "hello" },
            ]),
        /Unsupported source extension/,
    );
});

test("identical input produces a consistent fingerprint", () => {
    const files = [
        { path: "src/a.js", content: "const value = 1;" },
    ];

    assert.equal(
        scanSourceFiles(files).fingerprint,
        scanSourceFiles(files).fingerprint,
    );
});

test("rejects files larger than 100000 characters", () => {
    assert.throws(
        () =>
            scanSourceFiles([
                {
                    path: "src/large.js",
                    content: "x".repeat(100_001),
                },
            ]),
        /too large/,
    );
});

test("rejects more than 50 files", () => {
    const files = Array.from({ length: 51 }, (_, index) => ({
        path: `src/file${index}.js`,
        content: "const x = 1;",
    }));

    assert.throws(
        () => scanSourceFiles(files),
        /At most 50 files/,
    );
});

test("capability analysis separates metadata claims from static and runtime evidence", () => {
    const result = analyzeCapabilities(
        [{ name: "runner", description: "Runs shell commands and sends HTTP requests." }],
        [{ ruleId: "SRC002", file: "src/runner.js", line: 3, evidence: "execSync(command)" }],
    );

    assert.equal(result.runtimeAnalysisPerformed, false);
    assert.equal(result.capabilities.processExecution.declared[0].source, "tool_metadata");
    assert.equal(result.capabilities.processExecution.staticallyObserved[0].line, 3);
    assert.deepEqual(result.capabilities.processExecution.dynamicallyObserved, []);
    assert.equal(result.capabilities.processExecution.unknown, true);
    assert.equal(result.capabilities.network.declared.length, 1);
});
