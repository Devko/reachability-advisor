const express = require("express");
const router = express.Router();

router.get("/search", (req, res) => {
  res.send(`<h1>${req.query.q}</h1>`);
});

module.exports = router;
