const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

// MongoDB User Schema
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
});
const User = mongoose.model("User", UserSchema);

// Vulnerable: rounds too low
function hashPassword(password) {
  return bcrypt.hashSync(password, 4);
}

// Vulnerable: algorithm none
function generateToken(user) {
  return jwt.sign(user, "secret", { algorithm: "none" });
}

module.exports = { hashPassword, generateToken, User };
