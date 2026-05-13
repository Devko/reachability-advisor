const express = require("express");
const ejs = require("ejs");

const app = express();

app.get("/preview", (req, res) => {
  const html = ejs.render(String(req.query.template || ""), {
    user: req.query.user
  });
  res.send(html);
});

module.exports = app;
