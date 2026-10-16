// MCP Warden — Express-compatible app factory.
//
// NOTE: This build uses a zero-dependency HTTP shim (see ./http-shim.js)
// because the npm registry is unreachable in this environment. The public
// surface mirrors Express closely: app.use(), app.get(), res.status().json(),
// and next()-chained middleware. When network access is available, swap the
// shim import back to real `express` and `cors` without changing this file.

import http from "node:http";
import { createApp } from "./http-shim.js";
import healthRoutes from "./routes/health.routes.js";
import notFound from "./middleware/not-found.js";
import errorHandler from "./middleware/error-handler.js";

const app = createApp();

// --- CORS -----------------------------------------------------------------
// Read allowed origins from env. Default to the Vite dev server (5173).
// Never fall back to "*" in production.
const RAW_ORIGINS = process.env.CORS_ORIGINS ?? "http://localhost:5173";
const allowedOrigins = RAW_ORIGINS.split(",")
  .map((o) => o.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin) return next(); // same-origin / server-to-server call
  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    if (req.method === "OPTIONS") {
      res.status(204).end();
      return;
    }
    return next();
  }
  // Reject disallowed origins explicitly (mirrors cors()'s error callback).
  next(new Error(`CORS: origin ${origin} not allowed`));
});

// --- Parsing --------------------------------------------------------------
app.use((req, res, next) => {
  let body = "";
  req.setEncoding("utf8");
  req.on("data", (chunk) => {
    body += chunk;
    if (body.length > 1_000_000) {
      // 1mb limit
      req.destroy();
      res.status(413).json({
        success: false,
        error: { code: "PAYLOAD_TOO_LARGE", message: "Request body exceeds 1mb limit" },
      });
    }
  });
  req.on("end", () => {
    req.body = body;
    next();
  });
  req.on("error", next);
});

// --- Routes ---------------------------------------------------------------
app.use("/api/health", healthRoutes);

// --- 404 + errors ---------------------------------------------------------
app.use(notFound);
errorHandler.isErrorHandler = true;
app.use(errorHandler);

export default app;