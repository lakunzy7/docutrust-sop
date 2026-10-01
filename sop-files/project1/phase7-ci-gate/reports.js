// Deliberately vulnerable. This file exists for one purpose: to prove that the
// CI gate blocks a new SQL injection, by introducing one and watching the
// pipeline refuse it.
//
// It is seeded on a throwaway branch and never merged. It is also not wired
// into the application -- src/index.js does not require it -- so the endpoint
// below cannot be reached even by someone who finds this branch. The scanner
// reads files, not routes, which is the whole reason a static gate catches
// this before it ever runs.
//
// Note what this file is NOT: it is not the seeded finding from Project 1.
// That one was fixed in Phase 6. This is a fresh, previously unseen violation,
// in a different shape, written after the fix -- which is what makes the gate's
// refusal meaningful rather than a re-detection of something already known.

const express = require("express");
const router = express.Router();
const { pool } = require("../db");

router.get("/by-owner", async (req, res) => {
  const owner = req.query.owner;

  try {
    const query = `SELECT id, title FROM documents WHERE title ILIKE '%${owner}%'`;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    res.status(503).json({ error: "Database unavailable" });
  }
});

module.exports = router;
