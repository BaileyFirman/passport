import { Request } from 'express';
import { LogInOptions, LogOutOptions, LogInError, LogOutError } from "../../../sessionmanager";

type LogInCallback = (err: any) => Promise<any>;
type LogInA = [user: Express.User, options: LogInOptions];
type LogInB = [user: Express.User, options: LogInOptions, callback: LogInCallback];
type LogIn = [...args: LogInA | LogInB];

type LogOutCallback = (err: any) => Promise<any>;
type LogOutA = [user: LogOutOptions, callback: LogOutCallback];
type LogOutB = [callback: LogOutCallback];
type LogOut = [...args: LogOutA | LogOutB];

export default class RequestWrapper {
  req: Request;
  login: typeof RequestWrapper.prototype.logIn;
  logout: typeof RequestWrapper.prototype.logOut;

  constructor(req: Request) {
    this.req = req;

    this.logIn = this.logIn.bind(this);
    this.logOut = this.logOut.bind(this);
    this.login = this.logIn.bind(this);
    this.logout = this.logOut.bind(this);
    this.isAuthenticated = this.isAuthenticated.bind(this);
    this.isUnauthenticated = this.isUnauthenticated.bind(this);
  }

  async logIn(...args: LogInA): Promise<LogInError>
  async logIn(...args: LogInB): Promise<LogInError>
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

  async logOut(...args: LogOutA): Promise<LogOutError>
  async logOut(...args: LogOutB): Promise<LogOutError>
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

  isAuthenticated(): this is Express.AuthenticatedRequest {
    const property = this.req._userProperty ?? 'user';
    return !!this.req[property];
  }

  isUnauthenticated(): this is Express.UnauthenticatedRequest {
    return !this.req.isAuthenticated();
  }
}

module.exports = RequestWrapper;
