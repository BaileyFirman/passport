import { ExtendedRequest } from "../../../../types";
import { LogInOptions, LogOutOptions, LogInError, LogOutError } from "../../../sessionmanager";

type LogInCallback = (err: any) => Promise<any>;

type LogInA = [Express.User, LogInOptions];
type LogInB = [Express.User, LogInOptions, LogInCallback];
type LogIn = [...args: LogInA | LogInB];

type LogOutCallback = (err: any) => Promise<any>;
type LogOutA = [LogOutOptions, LogOutCallback];
type LogOutB = [LogOutCallback];
type LogOut = [...args: LogOutA | LogOutB];

class RequestWrapper {
  // The previous implementation of the class use `this` as an implicit parameter
  // that would monkey-patch request object with the methods.
  // This update means its now far easier to reason about 'this'
  req: ExtendedRequest;
  login: typeof RequestWrapper.prototype.logIn;
  logout: typeof RequestWrapper.prototype.logOut;

  constructor(req: ExtendedRequest) {
    this.req = req;

    this.logIn = this.logIn.bind(this);
    this.logOut = this.logOut.bind(this);
    this.login = this.logIn.bind(this);
    this.logout = this.logOut.bind(this);
    this.isAuthenticated = this.isAuthenticated.bind(this);
    this.isUnauthenticated = this.isUnauthenticated.bind(this);
  }

  async logIn(...args: LogIn): Promise<LogInError> {
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

  async logOut(...args: LogOut): Promise<LogOutError> {
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

  isAuthenticated(): boolean {
    const property = this.req._userProperty ?? 'user';
    return !!this.req[property];
  }

  isUnauthenticated(): boolean {
    return !this.req.isAuthenticated();
  }
}

export default RequestWrapper;
module.exports = RequestWrapper;