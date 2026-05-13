const express = require("express");
const cp = require("child_process");
const router = express.Router();

router.get("/host", (req, res) => {
  cp.exec(`host ${req.query.name}`, (error, stdout) => {
    res.send(error ? error.message : stdout);
  });
});

module.exports = router;
