const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// User login
function hashPassword(password) {
  return bcrypt.hashSync(password, 4);
}

// Generate token
function generateToken(user) {
  return jwt.sign(user, "secret", { algorithm: "none" });
}
