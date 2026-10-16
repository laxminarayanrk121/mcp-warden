# MCP Warden API Contract

Base URL (local development): **`http://localhost:4000`**

> **Implementation note (current build):** this milestone ships with a zero-dependency
> Express-compatible HTTP shim (`server/src/http-shim.js`) because the npm registry
> is unreachable in this environment. The public surface mirrors Express
> (`app.use`, `app.get`, `res.status().json`, `next(err)`, router mounting, CORS).
> When network access is available, delete the shim and replace the import in
> `server/src/app.js` with `import express from "express"` and `import cors from "cors"`.
> See the comment block at the top of `app.js` for the exact swap.

All endpoints are namespaced under `/api`. All responses are JSON.

---

## Implemented

### `GET /api/health`

Health check. Returns the current API status and version.

**Response — `200 OK`**

```json
{
  "status": "ok",
  "service": "mcp-warden-api",
  "version": "0.1.0"
}
```

---

## Available Routes

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/fixtures` | List built-in fixtures |
| `GET` | `/api/fixtures/:id` | Fetch a fixture manifest |
| `POST` | `/api/scan` | Scan a fixture or tool manifest; optionally include source files and a baseline |
| `POST` | `/api/baselines` | Create a metadata baseline |
| `GET` | `/api/baselines` | List saved baselines |
| `DELETE` | `/api/baselines/:id` | Delete a baseline |
| `POST` | `/api/compare` | Compare a fixture or manifest against a baseline |
| `GET` | `/api/reports` | List saved scan reports |
| `GET` | `/api/reports/:id` | Fetch a saved report as JSON |
| `GET` | `/api/reports/:id/md` | Fetch a saved report as Markdown |

### `POST /api/scan`

Provide exactly one of `fixtureId`, `manifest`, or the legacy top-level `tools` array. Source scanning is opt-in and accepts in-memory text only; source code is never executed.

```json
{
  "fixtureId": "benign",
  "includeSourceScan": true,
  "sourceFiles": [
    { "path": "src/example.js", "content": "eval(input);" }
  ],
  "baselineId": "6d6c9b543e30"
}
```

Successful responses include a `scanId`, timestamp, score and risk level, SHA-256 metadata fingerprint, findings, severity counts, capability analysis, baseline changes when compared, recommendations, and limitations. `capabilityAnalysis.runtimeAnalysisPerformed` is `false`; static results do not verify runtime behavior.

### `POST /api/baselines`

Create a baseline from a fixture or manifest:

```json
{ "fixtureId": "benign", "name": "approved-tools" }
```

### `POST /api/compare`

Compare a baseline with exactly one fixture or manifest:

```json
{ "baselineId": "6d6c9b543e30", "fixtureId": "suspicious" }
```

A detected metadata change is drift for review, not proof of malicious behavior.

---

## Error response format

All errors return this shape:

```json
{
  "success": false,
  "error": {
    "code": "NOT_FOUND",
    "message": "Route not found"
  }
}
```

| Status | Meaning |
| --- | --- |
| `404` | Unknown route (`NOT_FOUND`) |
| `403` | Origin not permitted by CORS (`CORS_DENIED`) |
| `500` | Internal server error (`INTERNAL_ERROR`). Stack traces are never included. |

---

## Running the backend

From the repository root:

```bash
# Install dependencies
npm run install:server

# Development mode (auto-restart)
npm run dev

# Production mode
npm start

# Run tests
npm test
```

Default URL: `http://localhost:4000`

## For the frontend developer

- The backend runs on **port 4000** by default. Override with the `PORT` env var.
- The Vite dev server should set `CORS_ORIGINS` to its own origin (e.g. `http://localhost:5173`).
- Use a relative `/api/...` path in the Vite proxy config, or set `VITE_API_BASE=http://localhost:4000` in the frontend environment.
- The routes listed above are implemented by the current backend.