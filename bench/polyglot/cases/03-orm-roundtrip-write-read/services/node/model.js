const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
  name: String,
  bio: String,
  email: String,
  role: { type: String, default: 'user' },
  isAdmin: { type: Boolean, default: false },
});
module.exports = mongoose.model('User', userSchema);
