import Passport from './passport';
import SessionManager, { LogInOptions, LogOutOptions } from './sessionmanager';
import SessionStrategy from './strategies/session';
import PassportStrategy from 'passport-strategy';

declare global {
  namespace Express {
      interface AuthInfo {}
      interface User {}

      interface Request {
          _userProperty?: string | undefined;
          _sessionManager?: SessionManager | undefined;
          [_userProperty: string]: any;

          authInfo?: AuthInfo | undefined;
          user?: User | undefined;

          login(user: User, done: (err: any) => void): Promise<void>;
          login(user: User, options: LogInOptions, done: (err: any) => void): Promise<void>;
          logIn(user: User, done: (err: any) => void): Promise<void>;
          logIn(user: User, options: LogInOptions, done: (err: any) => void): Promise<void>;


          logout(options: LogOutOptions, done: (err: any) => void): Promise<void>;
          logout(done: (err: any) => void): Promise<void>;
          logOut(options: LogOutOptions, done: (err: any) => void): Promise<void>;
          logOut(done: (err: any) => void): Promise<void>;

          isAuthenticated(): this is AuthenticatedRequest;
          isUnauthenticated(): this is UnauthenticatedRequest;
      }

      interface AuthenticatedRequest extends Request {
          user: User;
      }

      interface UnauthenticatedRequest extends Request {
          user?: undefined;
      }
  }
}

declare module 'express-session' {
  interface SessionData {
      messages: Array<string>;
      [_key: string]: any;
  }
}

declare module 'passport-strategy' {
  interface Strategy {
      name?: string | undefined;
  }
}

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
