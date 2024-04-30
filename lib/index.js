const Passport = require('./passport');
const SessionStrategy = require('./strategies/session');
const PassportStrategy = require('passport-strategy');

exports = module.exports = new Passport();

exports.Passport =
exports.Authenticator = Passport;
exports.Strategy = PassportStrategy;


exports.strategies = {};
exports.strategies.SessionStrategy = SessionStrategy;
