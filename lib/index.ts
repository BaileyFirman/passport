import Passport from './passport';
import SessionStrategy from './strategies/session';
import PassportStrategy from 'passport-strategy';

const passport = new Passport();

const strategies = {
  SessionStrategy,
};

export default passport;

export {
  Passport,
  Passport as Authenticator,
  PassportStrategy as Strategy,
  strategies
};

exports = module.exports = new Passport();
exports.Passport =
exports.Authenticator = Passport;
exports.Strategy = PassportStrategy;
exports.strategies = {};
exports.strategies.SessionStrategy = SessionStrategy;
