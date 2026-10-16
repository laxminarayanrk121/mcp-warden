import { VERSION } from "../config/version.js";

export function getHealth(_req, res) {
  res.status(200).json({
    status: "ok",
    service: "mcp-warden-api",
    version: VERSION,
  });
}