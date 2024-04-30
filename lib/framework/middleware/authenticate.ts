import { Response, NextFunction } from "express";
import { ExtendedRequest, ExtendedStrategy } from "../../../types";
import Passport from "../../passport";
import RequestWrapper from "./http/request";
import AuthenticationError from "../../errors/authenticationerror";

const { STATUS_CODES } = require('http');

export type AuthenticateOptions = {
  authInfo?: boolean;
  assignProperty?: string;
  failureFlash?: string | boolean | { type?: string; message?: string; };
  failureMessage?: string | boolean;
  failureRedirect?: string;
  failWithError?: boolean;
  keepSessionInfo?: boolean;
  session: boolean;
  scope?: string | string[];
  successFlash?: string | boolean | { type?: string; message?: string; };
  successMessage?: string | boolean;
  successRedirect?: string;
  successReturnToOrRedirect?: string;
  state?: string;
  pauseStream?: boolean;
  userProperty?: string;
  passReqToCallback?: boolean;
  prompt?: string;
};

type Failure = {
  challenge?: {
    type?: string;
    message?: string;
  };
  status?: number;
  type?: string;
};

export type AuthorizeOptions = AuthenticateOptions;

export type AuthenticateCallback = (
  err: any,
  user?: Express.User | false | null,
  info?: object | string | Array<string | undefined>,
  status?: number | Array<number | undefined>
) => any;

const authenticate = ({
  callback,
  name,
  options = { session: true },
  passport,
}: {
  callback?: AuthenticateCallback;
  name: string | string[];
  options?: AuthenticateOptions;
  passport: Passport;
}) => { 
  const nameIsArray = Array.isArray(name);
  const multi = nameIsArray;

  const names = nameIsArray ? name : [name];
  
  return (req: ExtendedRequest, res: Response, next: NextFunction) => {
    const request = new RequestWrapper(req);

    req.login = req.logIn = req.logIn ?? request.logIn;
    req.logout = req.logOut = req.logOut ?? request.logOut;
    req.isAuthenticated = req.isAuthenticated ?? request.isAuthenticated;
    req.isUnauthenticated = req.isUnauthenticated ?? request.isUnauthenticated;
    
    req._sessionManager = passport._sm;
    
    let failures: Array<Failure> = [];
    
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
      let challenge: Failure['challenge'] = failure.challenge ?? {};
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
    
      const rchallenge: Array<Failure['challenge']> = [];
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
        // @ts-ignore
        res.setHeader('WWW-Authenticate', rchallenge);
      }

      if (options.failWithError) {
        // @ts-ignore
        return next(new AuthenticationError(STATUS_CODES[res.statusCode], rstatus));
      }

      res.end(STATUS_CODES[res.statusCode]);
    }
    
    /**
     * @param {number} i 
     */
    const attempt = (i: number) => {
      let layer = names[i];

      if (!layer) {
        return allFailed();
      }

      let strategy: ExtendedStrategy;
      let prototype: ExtendedStrategy;

      // The original code assumes someone will make a mistake here, we can't resolve the type
      // @ts-ignore
      if (typeof layer.authenticate == 'function') {
        // @ts-ignore
        strategy = layer;
      } else {
        prototype = passport._strategy(layer);

        if (!prototype) {
          return next(new AuthenticationError('Unknown authentication strategy "' + layer + '"'));
        }
        
        strategy = Object.create(prototype);
      }
      
      strategy.success = (user: Express.User, info) => {
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
            // @ts-ignore
            passport.transformAuthInfo(info, req, (err, tinfo) => {
              if (err) {
                return next(err);
              }

              req.authInfo = tinfo as Express.AuthInfo;
              next();
            });
          } else {
            next();
          }
          return;
        }
      
        (async () => req.logIn(user, options, (err: any) => {
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
          };

          if (options.authInfo !== false) {
            // @ts-ignore
            passport.transformAuthInfo(info, req, (err, tinfo) => {
              if (err) {
                return next(err);
              }

              req.authInfo = tinfo as Express.AuthInfo;
              complete();
            });
          } else {
            complete();
          }
        }))();
      };

      // const fail: (...args: [any, number] | [number]) => void = (...args) => {
      //   const challenge = args.length === 2 ? args[0] : undefined;
      //   const status = args.length === 2 ? args[1] : args[0];

      //   failures.push({ challenge: challenge, status: status });
      //   attempt(i + 1);
      // };

      //@ts-ignore
      strategy.fail = (challenge, status) => {
        if (typeof challenge == 'number') {
          status = challenge;
          challenge = undefined;
        }

        failures.push({ challenge: challenge, status: status });
        attempt(i + 1);
      };
      
      // strategy.fail = fail;

      strategy.redirect = (url, status): void => {
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

export default authenticate;
module.exports = authenticate;