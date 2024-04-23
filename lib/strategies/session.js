const pause = require('pause');
const { Strategy } = require('passport-strategy');

/**
 * @typedef {import('../../types').Request} Request
 * @typedef {import('../../types').AuthenticateOptions} AuthenticateOptions
 */

class SessionStrategy extends Strategy {
  constructor({
    options,
    deserializeUser
  }) {
    super();

    this.name = 'session';
    this._key = options?.key ?? 'passport';
    this._deserializeUser = deserializeUser;
  }

  /**
   * 
   * @param {Request} req 
   * @param {AuthenticateOptions} [options]
   * @returns 
   */
  authenticate(req, options = {}) {
    if (!req.session) {
      return this.error(
        new Error(
          'Login sessions require session support. Did you forget to use `express-session` middleware?'
        )
      );
    }

    const sessionUser = req.session[this._key]
      ? req.session[this._key].user
      : null;

    if (sessionUser || sessionUser === 0) {
      const paused = options.pauseStream ? pause(req) : null;

      this._deserializeUser({ serializedUser: sessionUser, req, done: (err, user) => {
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
      }});
    } else {
      this.pass();
    }
  }
}

module.exports = SessionStrategy;
