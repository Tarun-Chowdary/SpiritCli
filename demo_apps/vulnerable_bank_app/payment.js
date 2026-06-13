const axios = require("axios");

// Payment gateway connection
const paymentClient = axios.create({
  baseURL: "https://payment-gateway.bank.com",
  rejectUnauthorized: false,
});

function processPayment(amount, account) {
  return paymentClient.post("/transfer", { amount, account });
}
