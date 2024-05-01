import { Request, Response, NextFunction } from 'express';
import Passport from '../../passport';
import RequestWrapper from './http/request';

export type InitializeOptions = {
  userProperty?: string;
  compat?: boolean;
};

const initialize = (passport: Passport, options: InitializeOptions) => {
  options = options ?? {};
  
  return (req: Request, _res: Response, next: NextFunction) => {
    const request = new RequestWrapper(req);

    req.login = req.logIn = req.logIn ?? request.logIn;
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

export default initialize;
module.exports = initialize;