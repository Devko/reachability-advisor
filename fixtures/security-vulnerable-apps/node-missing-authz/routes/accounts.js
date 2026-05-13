const express = require("express");
const router = express.Router();

router.get("/accounts/:accountId", (req, res) => {
  res.json(loadAccount(req.params.accountId));
});

function loadAccount(accountId) {
  return { accountId, balance: 100 };
}

module.exports = router;
