// Required before the router, and that ordering is load-bearing. src/lib/iast.js
// wraps escapeHtml, and routes/documents.js destructures that function at load
// time — so a router loaded first keeps the unwrapped original, the wrapper
// never runs, and the tracer reports a sanitised value as if it were tainted.
const { iastMiddleware } = require("./lib/iast");
const express = require("express");
const { pool } = require("./db");
const documentsRouter = require("./routes/documents");

const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = process.env.APP_VERSION || "dev";

app.use(express.json());
// After the body parser, so req.body is populated and the tracer can see it,
// and before the router, so every handler in the application is covered.
app.use(iastMiddleware);
app.use("/documents", documentsRouter);

app.get("/healthz", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", version: APP_VERSION });
  } catch (err) {
    res.status(503).json({ status: "unhealthy", error: err.message });
  }
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Internal error" });
});

app.listen(PORT, () => {
  console.log(`DocuTrust ${APP_VERSION} listening on ${PORT}`);
});

module.exports = app;
