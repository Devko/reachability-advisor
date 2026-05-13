const express = require("express");
const multer = require("multer");
const path = require("path");

const app = express();
const upload = multer({ dest: "/tmp/uploads" });

app.post("/upload", upload.single("archive"), (req, res) => {
  const target = path.join("/tmp/extract", req.file.originalname);
  res.json({ target });
});

module.exports = app;
