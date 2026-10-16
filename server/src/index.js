import app from "./app.js";

const PORT = Number(process.env.PORT) || 4000;

function startServer() {
  return new Promise((resolve, reject) => {
    const server = app.listen(PORT, () => {
      console.log(`MCP Warden API running on http://localhost:${PORT}`);
      resolve(server);
    });
    server.on("error", (err) => {
      if (err.code === "EADDRINUSE") {
        console.error(`Port ${PORT} is already in use. Set PORT env var to another value.`);
      } else {
        console.error("Server failed to start:", err.message);
      }
      reject(err);
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startServer().catch((err) => {
    console.error("Fatal: could not start server.", err);
    process.exit(1);
  });
}

export { startServer };