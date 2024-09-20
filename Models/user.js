const mongoose = require("mongoose");

const User = mongoose.model("User", {
  name: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  birthdate: { type: Date, required: true },
  gender: { type: String, enum: ["masculino", "feminino", "prefiro não identificar"], required: true },
  password: { type: String, required: true },
});

module.exports = User;
