/**
 * @typedef {import('../../../../types').Request} Request
 * 
 * @typedef {import('../../../../types').LoginOptions} LoginOptions
 * @typedef {import('../../../../types').LogoutOptions} LogoutOptions
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
    this.login = this.login.bind(this);
    this.logout = this.logout.bind(this);
    this.isAuthenticated = this.isAuthenticated.bind(this);
    this.isUnauthenticated = this.isUnauthenticated.bind(this);
  }

  /**
   * @param {{
   *   user: Express.User,
   *   options?: LoginOptions,
   *   callback: (err: any) => Promise<any>,
   * }} _ 
   * @returns 
   */
  async logIn({ user, options, callback } = { user: undefined, options: undefined, callback: undefined }) {
    options = options ?? {};
    
    const property = this.req._userProperty ?? 'user';
    const session = options.session === undefined ? true : options.session;
    
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
        return await callback();
      }
    } else {
      await callback?.();
    }
  }

  /**
   * @param {{
   *   options?: LogoutOptions,
   *   callback: (err: any) => Promise<any>,
   * }} _ 
   */
  async logOut({ options, callback } = { options: undefined, callback: undefined }) {
    options = options ?? {};

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
      await callback?.();
    }
  };

  /**
   * @param {{
  *   user: Express.User,
  *   options?: LoginOptions,
  *   callback: (err: any) => Promise<any>,
  * }} _ 
  * @returns 
  */
  async login({ user, options, callback } = { user: undefined, options: undefined, callback: undefined }) {
    return this.logIn({ user, options, callback });
  }

  /**
   * @param {{
  *   options?: LogoutOptions,
  *   callback: (err: any) => Promise<any>,
  * }} _ 
  */
  async logout({ options, callback } = { options: undefined, callback: undefined }) {
    return this.logOut({ options, callback });
  }

  isAuthenticated() {
    const property = this.req._userProperty ?? 'user';
    return !!this.req[property];
  }

  isUnauthenticated() {
    return !this.req.isAuthenticated();
  }
}

module.exports = RequestWrapper;
