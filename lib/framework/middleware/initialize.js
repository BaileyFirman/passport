const RequestWrapper = require('./http/request');

/**
 * @typedef {import('express').Response} Response
 * @typedef {import('express').NextFunction} NextFunction
 * 
 * @typedef {import('../../authenticator')} Passport
 * @typedef {import('../../../types').Request} Request
 * @typedef {import('../../../types').InitializeOptions} InitializeOptions
 */

/**
 * @param {Passport} passport
 * @param {InitializeOptions} options
 */
const initialize = (passport, options) => {
  options = options || {};
  
  /**
   * @param {Request} req
   * @param {Response} _res
   * @param {Function} next
   */
  return (req, _res, next) => {
    const request = new RequestWrapper(req);

    // We have tweaked logIn/logOut to be async

    // @ts-ignore
    req.login = req.logIn = req.logIn ?? request.logIn;
    // @ts-ignore
    req.logout = req.logOut = req.logOut ?? request.logOut;
    req.isAuthenticated = req.isAuthenticated ?? request.isAuthenticated;
    req.isUnauthenticated = req.isUnauthenticated ?? request.isUnauthenticated;
    
    req._sessionManager = passport._sm;
    
    if (options.userProperty) {
      req._userProperty = options.userProperty;
    }
    
    const { compat = true } = options;

    if (compat) {
      // @ts-ignore
      passport._userProperty = options.userProperty ?? 'user';
      
      // @ts-ignore
      req._passport = {};
      // @ts-ignore
      req._passport.instance = passport;
    }
    
    next();
  };
};

module.exports = initialize;
