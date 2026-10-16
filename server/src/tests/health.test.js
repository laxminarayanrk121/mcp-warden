import http from "node:http";
import test from "node:test";
import assert from "node:assert";
import app from "../app.js";

function request(path) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const addr = server.address();
      http.get(`http://127.0.0.1:${addr.port}${path}`, (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          server.close();
          resolve({ status: res.statusCode, headers: res.headers, body });
        });
      }).on("error", (err) => {
        server.close();
        reject(err);
      });
    });
    server.on("error", reject);
  });
}

test("GET /api/health returns 200 with expected JSON", async () => {
  const { status, headers, body } = await request("/api/health");

  assert.strictEqual(status, 200, `expected 200, got ${status}`);

  const contentType = headers["content-type"] || "";
  assert.ok(
    contentType.includes("application/json"),
    `expected JSON content-type, got ${contentType}`
  );

  const json = JSON.parse(body);
  assert.strictEqual(json.status, "ok");
  assert.strictEqual(json.service, "mcp-warden-api");
  assert.ok(typeof json.version === "string" && json.version.length > 0);
});

test("unknown route returns JSON 404", async () => {
  const { status, body } = await request("/api/does-not-exist");

  assert.strictEqual(status, 404);

  const json = JSON.parse(body);
  assert.strictEqual(json.success, false);
  assert.ok(json.error && typeof json.error.message === "string");
});

test("disallowed CORS origin is rejected", async () => {
  const { status, body } = await requestWithOrigin("/api/health", "http://evil.test");

  assert.strictEqual(status, 403);

  const json = JSON.parse(body);
  assert.strictEqual(json.success, false);
  assert.strictEqual(json.error.code, "CORS_DENIED");
});

function requestWithOrigin(path, origin) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const addr = server.address();
      const req = http.request(
        {
          hostname: "127.0.0.1",
          port: addr.port,
          path,
          headers: { Origin: origin },
        },
        (res) => {
          let body = "";
          res.on("data", (chunk) => (body += chunk));
          res.on("end", () => {
            server.close();
            resolve({ status: res.statusCode, headers: res.headers, body });
          });
        }
      );
      req.on("error", (err) => {
        server.close();
        reject(err);
      });
      req.end();
    });
    server.on("error", reject);
  });
}