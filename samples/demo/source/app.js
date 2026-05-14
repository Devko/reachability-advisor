const express = require("express");
const app = express();

app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.send(`<h1>${q}</h1>`);
});

app.post("/debug", (req, res) => {
  console.log(req.body);
  res.json({ok: true});
});

module.exports = app;
