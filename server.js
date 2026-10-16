const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    project: "MCP Warden",
    status: "Backend is running",
    system: 1
  });
});

app.listen(PORT, () => {
  console.log(`MCP Warden running at http://localhost:${PORT}`);
});
