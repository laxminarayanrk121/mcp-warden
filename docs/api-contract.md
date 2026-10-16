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

## Planned (not yet implemented)

These endpoints are documented for System 2 integration. They are **not implemented** in the current milestone. Do not call them yet.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/fixtures` | List available demo fixture scenarios |
| `POST` | `/api/scan` | Run a security scan over a fixture / manifest |
| `POST` | `/api/baselines` | Save a SHA-256 metadata baseline |
| `GET` | `/api/baselines` | List saved baselines |
| `POST` | `/api/compare` | Compare current manifest against a baseline |
| `GET` | `/api/reports/:id` | Fetch a stored scan report |

### Planned scan response schema

```json
{
  "scanId": "scan_0001",
  "score": 78,
  "riskLevel": "high",
  "fingerprint": "sha256:9f2c...",
  "findings": [
    {
      "ruleId": "DESC-INSTR-OVERRIDE",
      "severity": "high",
      "title": "Tool description contains instruction-override language",
      "evidence": "Ignore all previous instructions...",
      "remediation": "Remove the instruction-override phrasing from the tool description."
    }
  ]
}
```

Field definitions:

| Field | Type | Notes |
| --- | --- | --- |
| `scanId` | string | Unique identifier for the scan |
| `score` | integer | Heuristic risk score, `0`–`100` |
| `riskLevel` | string | `low` | `medium` | `high` | `critical` |
| `fingerprint` | string | `sha256:` prefix + hex digest of normalized tool metadata |
| `findings` | array | See finding object below |

### Planned finding object

| Field | Type | Notes |
| --- | --- | --- |
| `ruleId` | string | Stable identifier for the rule that fired |
| `severity` | string | `low` \| `medium` \| `high` \| `critical` |
| `title` | string | Human-readable description |
| `evidence` | string | The matched text or metadata that triggered the finding |
| `remediation` | string | Suggested action |

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
- Only the health endpoint is live right now. The other `/api/*` routes above are planned.