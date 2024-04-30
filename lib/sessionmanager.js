/**
 * @typedef {import('../types').Request} Request;
 * @typedef {import('./strategies/session').SessionStrategyOptions} SessionStrategyOptions;
 * @typedef {import('./passport').SerializeUser} SerializeUser
 * 
 * @typedef {{
 *   keepSessionInfo?: boolean;
 *   session?: boolean;    
 * }} LogInOptions
 * 
 * @typedef {{
 *   keepSessionInfo?: boolean;
 * }} LogOutOptions
 * 
 * @typedef {any} LogInError
 * 
 * @typedef {any} LogOutError
 */

/**
 * @param {{ [property: string]: any }} a
 * @param {{ [property: string]: any }} b
 */
const merge = (a, b) => {
  if (a && b) {
    for (const key in b) {
      a[key] = b[key];
    }
  }

  return a;
};

class SessionManager {
  /**
   * @param {{
   *   options: SessionStrategyOptions;
   *   serializeUser: SerializeUser;
   * }} _ 
   */
  constructor({
    options,
    serializeUser
  }) {
    this._key = (options && options.key) || 'passport';
    this._serializeUser = serializeUser;

    this.logIn = this.logIn.bind(this);
    this.logOut = this.logOut.bind(this);
  }

  /**
   * @param {{
   *   req: Request,
   *   user: Express.User,
   *   options: LogInOptions, 
   * }} _ 
   * @returns {Promise<any>}
   */
  async logIn({ req, user, options }) {
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
        /** @type {(err: Error, obj: any) => void} */
        (err, obj) => {
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

  /**
   * @param {{
   *   req: Request,
   *   options: LogInOptions, 
   * }} _ 
   * @returns {Promise<any>}
   */
  async logOut({ req, options }) {
    if (!req.session) {
      return new Error('Login sessions require session support. Did you forget to use `express-session` middleware?');
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

    if (options.keepSessionInfo) {
      merge(req.session, prevSession);

      return await new Promise((resolve) => {
        req.session.save((err) => resolve(err));
      });
    } else {
      return;
    }
  }
}

module.exports = SessionManager;
