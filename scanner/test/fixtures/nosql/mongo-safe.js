// MongoDB query with literal-only operators — no user input. Should NOT trigger.
const User = require('./model');

async function listActive() {
  return User.find({ $or: [{ status: 'active' }, { status: 'verified' }] });
}

async function countByType() {
  return User.countDocuments({ $type: 'string' });
}

module.exports = { listActive, countByType };
