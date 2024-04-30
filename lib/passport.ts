import FrameworkConnect from "./framework/connect";
import SessionManager from "./sessionmanager";
import SessionStrategy from "./strategies/session";
import { Strategy } from "passport-strategy";

import { AuthenticateCallback, AuthenticateOptions, AuthorizeOptions } from "./framework/middleware/authenticate";
import { InitializeOptions } from "./framework/middleware/initialize";
import AuthenticationError from "./errors/authenticationerror";

type TID = any;

type InitialInfo = unknown;

type SerializeUserCallback = (err: any, id?: TID) => void;
type SerializeUserA = [(user: Express.User, done: SerializeUserCallback) => void];
type SerializeUserB = [(req: Express.Request, user: Express.User, done: SerializeUserCallback) => void];

type _SerializeUserCallback = (err: any, serializedUser?: number | NonNullable<unknown>) => any;
type _SerializeUserA = [user: Express.User, done: _SerializeUserCallback];
type _SerializeUserB = [user: Express.User, req: Express.Request, done: _SerializeUserCallback];

type DeserializeUserCallback = (err: any, user?: Express.User | false | null) => void;
type DeserializeUserA = [(...args: [tid: TID, done: DeserializeUserCallback]) => void];
type DeserializeUserB = [(...args: [req: Express.Request, tid: TID, done: DeserializeUserCallback]) => void];

type _DeserializeUserCallback = (err: any, user?: Express.User | false) => any;
type _DeserializeUserA = [serializedUser: NonNullable<unknown>, req: Express.Request, done: _DeserializeUserCallback];
type _DeserializeUserB = [serializedUser: NonNullable<unknown>, done: _DeserializeUserCallback];

type TransformAuthInfoCallback = (err: any, info: any) => void;
type TransformAuthInfoA = [(info: any) => void];
type TransformAuthInfoB = [(info: any, done: TransformAuthInfoCallback) => void];
type TransformAuthInfoC = [(req: Express.Request, info: any, done: TransformAuthInfoCallback) => void];

type _TransformAuthInfoCallback = (err: any, transformedAuthInfo?: InitialInfo | NonNullable<unknown>) => any;
type _TransformAuthInfoA = [info: unknown, req: Express.Request, done: _TransformAuthInfoCallback];
type _TransformAuthInfoB = [info: unknown, done: _TransformAuthInfoCallback];

export default class Passport {
  _key: string;
  _strategies: { [name: string]: Strategy };
  _serializers: Array<SerializeUserA[0] | SerializeUserB[0]>;
  _deserializers: Array<DeserializeUserA[0] | DeserializeUserB[0]>;
  _infoTransformers: Array<TransformAuthInfoA[0] | TransformAuthInfoB[0] | TransformAuthInfoC[0]>;
  _framework: FrameworkConnect;
  _sm: SessionManager;

  constructor() {
    this._key = 'passport';
    this._strategies = {};
    this._serializers = [];
    this._deserializers = [];
    this._infoTransformers = [];
    this._framework = new FrameworkConnect();
    this._sm = new SessionManager({
      options: { key: this._key },
      serializeUser: this.serializeUser.bind(this),
    })

    this.use({
      strategy: new SessionStrategy({
        options: { key: this._key },
        deserializeUser: this.deserializeUser.bind(this),
      }),
    });
  }

  use({ name, strategy }: {
      name?: string;
      strategy: Strategy;
    }) {
    if (!name && strategy) {
      name = strategy.name;
    }
  
    if (!name) {
      throw new AuthenticationError('Authentication strategies must have a name');
    }
  
    this._strategies[name] = strategy;
  
    return this;
  }
  
  unuse(name: string) {
    delete this._strategies[name];
    return this;
  }

  framework(fw: FrameworkConnect) {
    this._framework = fw;
    return this;
  }

  sessionManager(sm: SessionManager) {
    this._sm = sm;
    return this;
  }

  initialize(options: InitializeOptions) {
    options = options ?? {};
    return this._framework.initialize(this, options);
  }

  authenticate(strategy: string, options: AuthenticateOptions, callback: AuthenticateCallback | undefined = undefined) {
    return this._framework.authenticate({
      passport: this,
      name: strategy,
      options,
      callback,
    });
  }

  authorize(strategy: string, options: AuthorizeOptions, callback: AuthenticateCallback | undefined = undefined) {
    options = options ?? {};
    options.assignProperty = 'account';

    const fn = this._framework.authorize ?? this._framework.authenticate;

    return fn({
      passport: this,
      name: strategy,
      options,
      callback,
    });
  }

  session(options: AuthenticateOptions) {
    return this.authenticate('session', options);
  }

  serializeUser(...args: SerializeUserA): void;
  serializeUser(...args: SerializeUserB): void;
  serializeUser(...args: _SerializeUserA): void;
  serializeUser(...args: _SerializeUserB): void;
  serializeUser(...args: SerializeUserA | SerializeUserB | _SerializeUserA | _SerializeUserB) {
    // Determine if we are using a public overload (fn registration)
    if (args.length === 1) {
      this._serializers.push(args[0]);
      return;
    }

    // Determine if we are using a private overload (fn invocation)
    if (args.length === 2 || args.length === 3) {
      const user = args[0];
      const req = args.length === 3 ? args[1] : undefined;
      const done = args.length === 3 ? args[2] : args[1];
    
      const stack = this._serializers;
  
      const pass: (i: number, err?: string, obj?: object) => void = (i, err, obj): void => {
        if (err === 'pass') {
          err = undefined;
        }
  
        if (err || obj || obj === 0) {
          return done(err, obj);
        }

        type Layer = SerializeUserA[0] | SerializeUserB[0];
  
        const layer: Layer | undefined = stack[i];
  
        if (!layer) {
          return done(new AuthenticationError('Failed to serialize user into session'));
        }
  
        const serialized: SerializeUserCallback = (e, o) => pass(i + 1, e, o);
  
        const isA = (x: Layer): x is SerializeUserA[0] => x.length === 2;
        const isB = (x: Layer): x is SerializeUserB[0] => x.length === 3;

        try {
          if (isB(layer) && req) {
            layer(req, user, serialized);
          } else if (isA(layer)) {
            layer(user, serialized);
          }
        } catch (e) {
          return done(e);
        }
      }
  
      pass(0);
    }
  }

  deserializeUser(...args: DeserializeUserA): void;
  deserializeUser(...args: DeserializeUserB): void;
  deserializeUser(...args: _DeserializeUserA): void;
  deserializeUser(...args: _DeserializeUserB): void;
  deserializeUser(...args: DeserializeUserA | DeserializeUserB | _DeserializeUserA | _DeserializeUserB) {
    if (args.length === 1) {
      this._deserializers.push(args[0]);
      return;
    }

    if(args.length === 2 || args.length === 3) {
      const serializedUser = args[0];
      const req = args.length === 3 ? args[1] : undefined;
      const done = args.length === 3 ? args[2] : args[1];
  
      const stack = this._deserializers;
  
      const pass: (i: number, err?: string, obj?: false | Express.User | null | undefined) => void = (i, err = '', user = undefined): void => {
        if ('pass' === err) {
          err = undefined;
        }
  
        if (err || user) {
          return done(err, user ?? undefined); // Undefined is a workaround for typing
        }
  
        if (user === null || user === false) {
          return done(null, false);
        }

        type Layer = DeserializeUserA[0] | DeserializeUserB[0];
  
        const layer: Layer | undefined = stack[i];
  
        if (!layer) {
          return done(new AuthenticationError('Failed to deserialize user out of session'));
        }
  
        const deserialized: DeserializeUserCallback = (e, u) => pass(i + 1, e, u);

        const isA = (x: Layer): x is DeserializeUserA[0] => x.length === 2;
        const isB = (x: Layer): x is DeserializeUserB[0] => x.length === 3;
  
        try {
          if (isB(layer) && req) {
            layer(req, serializedUser, deserialized);
          } else if (isA(layer)) {
            layer(serializedUser, deserialized);
          }
        } catch (e) {
          return done(e);
        }
      }
  
      pass(0);
    }
  }

  transformAuthInfo(...args: TransformAuthInfoA): void;
  transformAuthInfo(...args: TransformAuthInfoB): void;
  transformAuthInfo(...args: TransformAuthInfoC): void;
  transformAuthInfo(...args: _TransformAuthInfoA): void;
  transformAuthInfo(...args: _TransformAuthInfoB): void;
  transformAuthInfo(...args: TransformAuthInfoA | TransformAuthInfoB | TransformAuthInfoC | _TransformAuthInfoA | _TransformAuthInfoB): void {
    if (args.length === 1) {
      this._infoTransformers.push(args[0]);
      return;
    }

    if (args.length === 2 || args.length === 3) {
      const info = args[0];
      const req = args.length === 3 ? args[1] : undefined;
      const done = args.length === 3 ? args[2] : args[1];
  
      const stack = this._infoTransformers;
  
      const pass: (i: number, err?: string, obj?: NonNullable<unknown>) => void = (i, err, tinfo): void => {
        if (err === 'pass') {
          err = undefined;
        }
  
        if (err || tinfo) {
          return done(err, tinfo);
        }
  
        type Layer = TransformAuthInfoA[0] | TransformAuthInfoB[0] | TransformAuthInfoC[0];

        const layer: Layer | undefined = stack[i];
  
        if (!layer) {
          return done(null, info);
        }
  
        const transformed: TransformAuthInfoCallback = (e, t) => pass(i + 1, e, t);

        const isA = (x: Layer): x is TransformAuthInfoA[0] => x.length === 1;
        const isB = (x: Layer): x is TransformAuthInfoB[0] => x.length === 2;
        const isC = (x: Layer): x is TransformAuthInfoC[0] => x.length === 3;
  
        try {
          if (isA(layer)) {
            transformed(null, layer(info));
          } else if (isC(layer) && req) {
            layer(req, info, transformed);
          } else if (isB(layer)){
            layer(info, transformed);
          }
        } catch (e) {
          return done(e);
        }
      };
  
      pass(0);
    }
  }

  _strategy(name: string) {
    return this._strategies[name];
  }
}

module.exports = Passport;
