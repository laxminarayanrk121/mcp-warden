// Minimal Express-compatible shim built on Node's built-in `http` module.
//
// Purpose: keep the backend runnable and testable in this environment where
// the npm registry is unreachable. The public surface mirrors Express:
//   - createApp() returns an object with .use(), .get(), .post(), .delete(), .listen()
//   - res.status(code), res.json(obj), res.writeHead(), res.end()
//   - middleware chaining via next(err)
//   - router mounting: app.use("/api/health", router)
//
// When network access is available, delete this file and replace the import
// in app.js with:
//   import express from "express";
//   import cors from "cors";
//   const app = express();
//   app.use(cors(corsOptions));
//   app.use(express.json({ limit: "1mb" }));

import http from "node:http";

function makeResObject(res) {
  if (res._mcpWarden) return res;
  const out = {
    statusCode: 200,
    headers: {},
    _mcpWarden: true,
    _ended: false,
    status(code) {
      this.statusCode = code;
      return this;
    },
    setHeader(key, value) {
      this.headers[key] = value;
      return this;
    },
    json(obj) {
      const body = JSON.stringify(obj);
      if (!this.headers["Content-Type"]) this.headers["Content-Type"] = "application/json";
      this._ended = true;
      res.writeHead(this.statusCode, this.headers);
      res.end(body);
      return this;
    },
    send(body) {
      if (typeof body !== "string" && !Buffer.isBuffer(body)) body = String(body);
      this._ended = true;
      res.writeHead(this.statusCode, this.headers);
      res.end(body);
      return this;
    },
    end() {
      this._ended = true;
      res.writeHead(this.statusCode, this.headers);
      res.end();
      return this;
    },
  };
  return out;
}

function isRouter(obj) {
  return obj && typeof obj === "object" && (typeof obj.get === "function" || typeof obj.use === "function" || typeof obj.delete === "function" || typeof obj.post === "function");
}

export function createRouter() {
  const routes = [];
  return {
    use(middleware) {
      if (typeof middleware !== "function") throw new TypeError("router.use() requires a function");
      routes.push({ type: "use", fn: middleware });
      return this;
    },
    get(path, handler) {
      routes.push({ type: "route", method: "GET", path, handler });
      return this;
    },
    post(path, handler) {
      routes.push({ type: "route", method: "POST", path, handler });
      return this;
    },
    delete(path, handler) {
      routes.push({ type: "route", method: "DELETE", path, handler });
      return this;
    },
    _routes: routes,
  };
}

export function createApp() {
  const routes = [];
  const app = {
    use(prefix, middleware) {
      // Support router mounting: app.use("/api/health", router)
      if (typeof prefix === "function") {
        routes.push({ type: "use", isErrorHandler: !!prefix.isErrorHandler, fn: prefix });
        return app;
      }
      if (isRouter(middleware)) {
        for (const r of middleware._routes) {
          routes.push({ ...r, prefix });
        }
        return app;
      }
      if (typeof middleware === "function") {
        routes.push({ type: "use", isErrorHandler: !!middleware.isErrorHandler, fn: middleware });
        return app;
      }
      throw new TypeError("app.use() requires a function or router");
    },
    get(path, handler) {
      routes.push({ type: "route", method: "GET", path, handler });
      return app;
    },
    post(path, handler) {
      routes.push({ type: "route", method: "POST", path, handler });
      return app;
    },
    delete(path, handler) {
      routes.push({ type: "route", method: "DELETE", path, handler });
      return app;
    },
    listen(port, cb) {
      const server = http.createServer((req, res) => {
        const resObj = makeResObject(res);
        let i = 0;

        const next = (err) => {
          if (resObj._ended) return; // response already sent
          if (err) return runError(err);
          const step = routes[i++];
          if (!step) {
            resObj.statusCode = 404;
            resObj.json({
              success: false,
              error: { code: "NOT_FOUND", message: "Route not found" },
            });
            return;
          }
          try {
            if (step.type === "use") {
              step.fn(req, resObj, next);
            } else if (step.type === "route") {
              if (req.method !== step.method) return next();
              const path = req.url || "";
              let matched = false;
              if (step.prefix) {
                // Mounted router: prefix "/" matches anything under it.
                if (step.prefix === "/") matched = true;
                else if (path === step.prefix) matched = true;
                else if (path.startsWith(step.prefix + "/")) matched = true;
                // Sub-path within the mounted router.
                const subPath = path === step.prefix ? "/" : path.slice(step.prefix.length);
                matched = matched && (subPath === step.path || subPath.startsWith(step.path));
              } else {
                matched = path === step.path;
              }
              if (matched) {
                step.handler(req, resObj, next);
              } else {
                next();
              }
            }
          } catch (e) {
            next(e);
          }
        };

        const runError = (err) => {
          let j = routes.length - 1;
          while (j >= 0 && !(routes[j].type === "use" && routes[j].isErrorHandler)) j--;
          if (j < 0) {
            resObj.statusCode = 500;
            resObj.json({ success: false, error: { code: "INTERNAL_ERROR", message: err?.message || "Internal server error" } });
            return;
          }
          routes[j].fn(err, req, resObj, () => {});
        };

        req.on("error", next);
        next();
      });
      server.listen(port, cb);
      return server;
    },
  };
  return app;
}

export default { createApp, createRouter };
