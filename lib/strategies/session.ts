const pause = require('pause');
import { Strategy } from 'passport-strategy';
import Passport from '../passport';
import { AuthenticateOptions } from '../framework/middleware/authenticate';
import AuthenticationError from '../errors/authenticationerror';

export type SessionStrategyOptions = {
  key: string;
};

export default class SessionStrategy extends Strategy {
  public name: string;
  private _key: string;
  private _deserializeUser: Passport['deserializeUser'];

  constructor({
    options,
    deserializeUser
  }: {
    options: SessionStrategyOptions;
    deserializeUser: Passport['deserializeUser'];
  }) {
    super();

    this.name = 'session';
    this._key = options?.key ?? 'passport';
    this._deserializeUser = deserializeUser;
  }

  authenticate(req: Express.Request, options: AuthenticateOptions = {
    session: true
  }) {
    if (!req.session) {
      return this.error(
        new AuthenticationError(
          'Login sessions require session support. Did you forget to use `express-session` middleware?'
        )
      );
    }

    const sessionUser = req.session[this._key]
      ? req.session[this._key].user
      : null;

    if (sessionUser || sessionUser === 0) {
      const paused = options.pauseStream
        ? pause(req)
        : null;

      this._deserializeUser(
        sessionUser,
        req,
        (err: any, user: any) => {
          if (err) {
            return this.error(err);
          }
  
          if (user) {
            const property = req._userProperty ?? 'user';

            req[property] = user;
          } else {
            delete req.session[this._key].user;
          }
  
          this.pass();
  
          if (paused) {
            paused.resume();
          }
        });
    } else {
      this.pass();
    }
  }
}

module.exports = SessionStrategy;
