const { STATUS_CODES } = require('http');
const RequestWrapper = require('./http/request');
const AuthenticationError = require('../../errors/authenticationerror');

/**
 * @typedef {import('express').Response} Response
 * @typedef {import('express').NextFunction} NextFunction
 * 
 * @typedef {import('../../authenticator')} Passport
 * @typedef {import('../../../types').Strategy} Strategy
 * @typedef {import('../../../types').Request} Request
 * @typedef {import('../../../types').InitializeOptions} InitializeOptions
 * @typedef {import('../../../types').AuthenticateOptions} AuthenticateOptions
 * @typedef {import('../../../types').AuthenticateCallback} AuthenticateCallback
 */


/**
 * @param {{
 *  callback?: AuthenticateCallback,
 *  name: string | string[],
 *  options?: AuthenticateOptions,
 *  passport: Passport
 * }} _
 */
const authenticate = ({
  callback,
  name,
  options = {},
  passport,
}) => { 
  const nameIsArray = Array.isArray(name);
  const multi = nameIsArray;

  const names = nameIsArray ? name : [name];
  
  /**
   * @param {Request} req
   * @param {Response} res
   * @param {Function} next
   */
  return (req, res, next) => {
    const request = new RequestWrapper(req);

    // We have tweaked logIn/logOut to be async

    // @ts-ignore
    req.login = req.logIn = req.logIn ?? request.logIn;
    // @ts-ignore
    req.logout = req.logOut = req.logOut ?? request.logOut;
    req.isAuthenticated = req.isAuthenticated ?? request.isAuthenticated;
    req.isUnauthenticated = req.isUnauthenticated ?? request.isUnauthenticated;
    
    req._sessionManager = passport._sm;
    
    let failures = [];
    
    const allFailed = () => {
      if (callback) {
        if (multi) {
          const challenges = failures.map(f => f.challenge);
          const statuses = failures.map(f => f.status);

          return callback(null, false, challenges, statuses);
        } else {
          return callback(null, false, failures[0].challenge, failures[0].status);
        }
      }
      
      let failure = failures[0] ?? {};
      let challenge = failure.challenge ?? {};
      let msg;
    
      if (options.failureFlash) {
        let flash = options.failureFlash;

        if (typeof flash == 'string') {
          flash = { type: 'error', message: flash };
        }

        // Overlooked case in original code
        if(typeof flash == 'boolean') {
          flash = { type: challenge.type, message: undefined };
        }

        flash.type = flash.type ?? 'error';
      
        let type = flash.type ?? challenge.type ?? 'error';
        msg = flash.message ?? challenge.message ?? challenge;
        if (typeof msg == 'string') {
          req.flash(type, msg);
        }
      }

      if (options.failureMessage) {
        msg = options.failureMessage;

        if (typeof msg == 'boolean') {
          msg = challenge.message ?? challenge;
        }

        if (typeof msg == 'string') {
          req.session.messages = req.session.messages || [];
          req.session.messages.push(msg);
        }
      }

      if (options.failureRedirect) {
        return res.redirect(options.failureRedirect);
      }
    
      const rchallenge = [];
      let rstatus;
      let status;
      
      for (let j = 0; j < failures.length; j++) {
        failure = failures[j];
        challenge = failure.challenge;
        status = failure.status;
        rstatus = rstatus ?? status;

        if (typeof challenge == 'string') {
          rchallenge.push(challenge);
        }
      }
    
      res.statusCode = rstatus ?? 401;

      if (res.statusCode == 401 && rchallenge.length) {
        res.setHeader('WWW-Authenticate', rchallenge);
      }

      if (options.failWithError) {
        return next(new AuthenticationError(STATUS_CODES[res.statusCode], rstatus));
      }

      res.end(STATUS_CODES[res.statusCode]);
    }
    
    /**
     * @param {number} i 
     */
    const attempt = (i) => {
      let layer = names[i];

      if (!layer) {
        return allFailed();
      }

      /** @type {Strategy} */
      let strategy;
      /** @type {Strategy} */
      let prototype;

      // The original code assumes someone will make a mistake here, we can't resolve the type
      // @ts-ignore
      if (typeof layer.authenticate == 'function') {
        // @ts-ignore
        strategy = layer;
      } else {
        prototype = passport._strategy(layer);

        if (!prototype) {
          return next(new Error('Unknown authentication strategy "' + layer + '"'));
        }
        
        strategy = Object.create(prototype);
      }
      
      strategy.success = (user, info) => {
        if (callback) {
          return callback(null, user, info);
        }
      
        info = info ?? {};

        let msg;
      
        if (options.successFlash) {
          let flash = options.successFlash;

          if (typeof flash == 'string') {
            flash = { type: 'success', message: flash };
          }

          // Overlooked case in original code
          if(typeof flash == 'boolean') {
            flash = { type: info.type, message: undefined };
          }

          flash.type = flash.type ?? 'success';
        
          let type = flash.type ?? info.type ?? 'success';

          msg = flash.message ?? info.message ?? info;

          if (typeof msg == 'string') {
            req.flash(type, msg);
          }
        }

        if (options.successMessage) {
          msg = options.successMessage;

          if (typeof msg == 'boolean') {
            msg = info.message ?? info;
          }

          if (typeof msg == 'string') {
            req.session.messages = req.session.messages ?? [];
            req.session.messages.push(msg);
          }
        }
        if (options.assignProperty) {
          req[options.assignProperty] = user;

          if (options.authInfo !== false) {
            passport.transformAuthInfo({ info, req, done: (err, tinfo) => {
              if (err) {
                return next(err);
              }

              req.authInfo = tinfo;
              next();
            }});
          } else {
            next();
          }
          return;
        }
      
        (async () => await req.logIn({ user, options, callback: (err) => {
          if (err) {
            return next(err);
          }
          
          const complete = () => {
            if (options.successReturnToOrRedirect) {
              let url = options.successReturnToOrRedirect;

              if (req.session && req.session.returnTo) {
                url = req.session.returnTo;
                delete req.session.returnTo;
              }

              return res.redirect(url);
            }

            if (options.successRedirect) {
              return res.redirect(options.successRedirect);
            }
            next();
          }
          
          if (options.authInfo !== false) {
            passport.transformAuthInfo({ info, req, done: (err, tinfo) => {
              if (err) {
                return next(err);
              }

              req.authInfo = tinfo;
              complete();
            }});
          } else {
            complete();
          }
        }}))();
      };
      
      strategy.fail = (challenge, status) => {
        if (typeof challenge == 'number') {
          status = challenge;
          challenge = undefined;
        }

        failures.push({ challenge: challenge, status: status });
        attempt(i + 1);
      };

      /** @type {(url: string, status: number) => void} */
      strategy.redirect = (url, status) => {
        res.statusCode = status ?? 302;
        res.setHeader('Location', url);
        res.setHeader('Content-Length', '0');
        res.end();
      };
      
      strategy.pass = () => next();
      
      strategy.error = (err) => callback ? callback(err) : next(err);
    
      strategy.authenticate(req, options);
    };

    attempt(0);
  };
};

module.exports = authenticate;
