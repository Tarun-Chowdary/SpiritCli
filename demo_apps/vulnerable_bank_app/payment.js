const axios = require("axios");
const lodash = require("lodash");
const express = require("express");

const router = express.Router();

// Missing helmet setup — triggers detection
const app = express();

// Vulnerable: CORS wildcard
app.use(cors({ origin: "*" }));

// Vulnerable: TLS disabled
const paymentClient = axios.create({
  baseURL: "https://payment-gateway.bank.com",
  rejectUnauthorized: false,
});

// Vulnerable: prototype pollution
function processPayment(req) {
  const payload = lodash.merge({}, req.body);
  return paymentClient.post("/transfer", payload);
}

router.post("/pay", (req, res) => {
  processPayment(req)
    .then((result) => res.json(result.data))
    .catch((err) => res.status(500).json({ error: err.message }));
});

module.exports = router;
