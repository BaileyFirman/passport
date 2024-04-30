/**
 * @typedef {import('../../../../types').Request} Request
 * @typedef {import('../../../sessionmanager').LogInOptions} LogInOptions
 * @typedef {import('../../../sessionmanager').LogOutOptions} LogOutOptions
 * @typedef {import('../../../sessionmanager').LogInError} LogInError
 * @typedef {import('../../../sessionmanager').LogOutError} LogOutError
 * 
 * @typedef {(err: any) => Promise<any>} LogInCallback
 * @typedef {[Express.User, LogInOptions]} LogInA
 * @typedef {[Express.User, LogInOptions, LogInCallback]} LogInB
 * @typedef {[...args: LogInA | LogInB]} LogIn
 * 
 * @typedef {(err: any) => Promise<any>} LogOutCallback
 * @typedef {[LogOutOptions, LogOutCallback]} LogOutA
 * @typedef {[LogOutCallback]} LogOutB
 * @typedef {[...args: LogOutA | LogOutB]} LogOut
 */

class RequestWrapper {
  // The previous implementation of the class use `this` as an implicit parameter
  // that would monkey-patch request object with the methods.
  // This update means its now far easier to reason about 'this'

  /**
   * 
   * @param {Request} req 
   */
  constructor(req) {
    this.req = req;

    this.logIn = this.logIn.bind(this);
    this.logOut = this.logOut.bind(this);
    this.login = this.logIn.bind(this);
    this.logout = this.logOut.bind(this);
    this.isAuthenticated = this.isAuthenticated.bind(this);
    this.isUnauthenticated = this.isUnauthenticated.bind(this);
  }

  /**
   * @param {LogIn} args
   * @returns {Promise<LogInError>}
   */
  async logIn(...args) {
    const user = args[0];
    const options = typeof args[1] === 'object' ? args[1] : {};
    const callback = typeof args[1] === 'function' ? args[1] : args[2];
    
    const property = this.req._userProperty ?? 'user';
    const session = options.session ?? true;
    
    this.req[property] = user;
  
    if (session && this.req._sessionManager) {
      if (typeof callback != 'function') {
        throw new Error('req#login requires a callback function');
      }
  
      const logInError = await this.req._sessionManager.logIn({
        options,
        req: this.req,
        user,
      });

      if (logInError) {
        this.req[property] = null;
        return await callback(logInError);
      } else {
        return await callback(undefined);
      }
    } else {
      await callback?.(undefined);
    }
  }

  /**
   * @param {LogOut} args
   * @returns {Promise<LogOutError>}
   */
  async logOut(...args) {
    const options = typeof args[0] === 'object' ? args[0] : {};
    const callback = typeof args[0] === 'function' ? args[0] : args[1];

    const property = this.req._userProperty ?? 'user';
    
    this.req[property] = null;

    if (this.req._sessionManager) {
      if (typeof callback !== 'function') {
        throw new Error('req#logout requires a callback function');
      }
      
      const logOutError = await this.req._sessionManager.logOut({
        options,
        req: this.req,
      });

      await callback(logOutError);
    } else {
      await callback?.(undefined);
    }
  };

  /**
   * @returns {boolean}
   */
  isAuthenticated() {
    const property = this.req._userProperty ?? 'user';
    return !!this.req[property];
  }

  /**
   * @returns {boolean}
   */
  isUnauthenticated() {
    return !this.req.isAuthenticated();
  }
}

module.exports = RequestWrapper;
