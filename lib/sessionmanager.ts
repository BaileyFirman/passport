import Passport from './passport';
import { SessionStrategyOptions } from './strategies/session';

export type LogInOptions = {
  keepSessionInfo?: boolean;
  session?: boolean;
};

export type LogOutOptions = {
  keepSessionInfo?: boolean;
};

export type LogInError = any;
export type LogOutError = any;

const merge = (a: { [property: string]: any; }, b: { [property: string]: any; }) => {
  if (a && b) {
    for (const key in b) {
      a[key] = b[key];
    }
  }

  return a;
};

export default class SessionManager {
  private _key: string;
  private _serializeUser: Passport['serializeUser'];

  constructor({
    options,
    serializeUser
  }: {
    options: SessionStrategyOptions;
    serializeUser: Passport['serializeUser'];
  }) {
    this._key = options?.key ?? 'passport';
    this._serializeUser = serializeUser;

    this.logIn = this.logIn.bind(this);
    this.logOut = this.logOut.bind(this);
  }

  async logIn({ req, user, options }: {
    req: Express.Request;
    user: Express.User;
    options: LogInOptions;
  }): Promise<LogInError> {
    if (!req.session) {
      return new Error(
        'Login sessions require session support. Did you forget to use `express-session` middleware?',
      );
    }

    const prevSession = req.session;

    const regenerateError = await new Promise((resolve) => {
      req.session.regenerate((err) => resolve(err));
    });

    if (regenerateError) {
      return regenerateError;
    }

    const serializeError = await new Promise((resolve) => {
      this._serializeUser(
        user,
        req,
        (err: any, obj: any) => {
          if (err) {
            return resolve(err);
          }

          if (options.keepSessionInfo) {
            merge(req.session, prevSession);
          }

          if (!req.session[this._key]) {
            req.session[this._key] = {};
          }

          req.session[this._key].user = obj;

          resolve(undefined);
        });
    });

    if (serializeError) {
      return serializeError;
    }

    return await new Promise((resolve) => {
      req.session.save((err) => resolve(err));
    });
  }

  async logOut({ req, options }: {
    req: Express.Request;
    options: LogOutOptions;
  }): Promise<LogOutError> {
    if (!req.session) {
      return new Error(
        'Login sessions require session support. Did you forget to use `express-session` middleware?',
      );
    }

    if (req.session[this._key]) {
      delete req.session[this._key].user;
    }

    const prevSession = req.session;

    const saveError = await new Promise((resolve) => {
      req.session.save((err) => resolve(err));
    });

    if (saveError) {
      return saveError;
    }

    const regenerateError = await new Promise((resolve) => {
      req.session.regenerate((err) => resolve(err));
    });

    if (regenerateError) {
      return regenerateError;
    }

    if (!options.keepSessionInfo) {
      return;
    }
    
    merge(req.session, prevSession);

    return await new Promise((resolve) => {
      req.session.save((err) => resolve(err));
    });
  }
}

module.exports = SessionManager;
