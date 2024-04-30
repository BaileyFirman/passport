const SessionStrategy = require('./strategies/session');
const SessionManager = require('./sessionmanager');
const FrameworkConnect = require('./framework/connect');

/**
 * @typedef {import('../types').Request} Request
 * @typedef {import('../types').Strategy} Strategy
 * @typedef {import('./framework/middleware/authenticate').AuthenticateOptions} AuthenticateOptions
 * @typedef {import('./framework/middleware/authenticate').AuthenticateCallback} AuthenticateCallback
 * @typedef {import('./framework/middleware/initialize').InitializeOptions} InitializeOptions
 * @typedef {import('./framework/middleware/authenticate').AuthorizeOptions} AuthorizeOptions
 */

/**
 * @typedef {any} TID
 * @typedef {unknown} InitialInfo
 * 
 * // BEGIN SerializeUser
 * @typedef {(err: any, id?: TID) => void} SerializeUserCallback
 * @typedef {[(user: Express.User, callback: SerializeUserCallback) => void]} SerializeUserA // First public overload
 * @typedef {[(req: Request, user: Express.User, callback: SerializeUserCallback) => void]} SerializeUserB // Second public overload
 *
 * @typedef {(err: any, serializedUser?: number | NonNullable<unknown>) => any} _SerializeUserCallback
 * @typedef {[Express.User, _SerializeUserCallback]} _SerializeUserA // First private overload
 * @typedef {[Express.User, Request, _SerializeUserCallback]} _SerializeUserB // Second private overload
 * 
 * @typedef {(...args: SerializeUserA | SerializeUserB | _SerializeUserA | _SerializeUserB) => void} SerializeUser
 * // END SerializeUser
 * 
 * // BEGIN DeserializeUser
 * @typedef {(err: any, user?: Express.User | false | null) => void} DeserializeUserCallback
 * @typedef {[(...args: [TID, DeserializeUserCallback]) => void]} DeserializeUserA // First public overload
 * @typedef {[(...args: [Request, TID, DeserializeUserCallback]) => void]} DeserializeUserB // Second public overload
 * 
 * @typedef {(err: any, user?: Express.User | false) => any} _DeserializeUserCallback
 * @typedef {[NonNullable<unknown>, Request, _DeserializeUserCallback]} _DeserializeUserA // First private overload
 * @typedef {[NonNullable<unknown>, _DeserializeUserCallback]} _DeserializeUserB // Second private overload
 * 
 * @typedef {(...args: DeserializeUserA | DeserializeUserB | _DeserializeUserA | _DeserializeUserB) => void} DeserializeUser
 * // END DeserializeUser
 * 
 * // BEGIN TransformAuthInfo
 * @typedef {(err: any, info: any) => void} TransformAuthInfoCallback
 * @typedef {[(info: any) => void]} TransformAuthInfoA // First public overload
 * @typedef {[(info: any, done: TransformAuthInfoCallback) => void]} TransformAuthInfoB // Second public overload
 * @typedef {[(req: Request, info: any, done: TransformAuthInfoCallback) => void]} TransformAuthInfoC // Third public overload
 * 
 * @typedef {(err: any, transformedAuthInfo?: InitialInfo | NonNullable<unknown>) => any} _TransformAuthInfoCallback
 * @typedef {[unknown, Request, _TransformAuthInfoCallback]} _TransformAuthInfoA // First private overload
 * @typedef {[unknown, _TransformAuthInfoCallback]} _TransformAuthInfoB // Second private overload
 * 
 * @typedef {(...args: TransformAuthInfoA | TransformAuthInfoB | TransformAuthInfoC | _TransformAuthInfoA | _TransformAuthInfoB) => void} TransformAuthInfo
 * // END TransformAuthInfo
 */

class Passport {
  constructor() {
    /** @type {string} */
    this._key = 'passport';
    /** @type {{ [name: string]: Strategy }} */
    this._strategies = {};
    /** @type {Array<SerializeUserA[0] | SerializeUserB[0]>} */
    this._serializers = [];
    /** @type {Array<DeserializeUserA[0] | DeserializeUserB[0]>} */
    this._deserializers = [];
    /** @type {Array<TransformAuthInfoA[0] | TransformAuthInfoB[0] | TransformAuthInfoC[0]>} */
    this._infoTransformers = [];
    /** @type {FrameworkConnect} */
    this._framework = new FrameworkConnect();

    this
      .use({
        strategy: new SessionStrategy({
          options: { key: this._key },
          deserializeUser: this.deserializeUser.bind(this),
        }),
      })
      .sessionManager(new SessionManager({
        options: { key: this._key },
        serializeUser: this.serializeUser.bind(this),
      }));
  }

  /**
   * @param {{
   *   name?: string,
   *   strategy: Strategy
   * }} _
   */
  use({ name, strategy }) {
    if (!name && strategy) {
      name = strategy.name;
    }
  
    if (!name) {
      throw new Error('Authentication strategies must have a name');
    }
  
    this._strategies[name] = strategy;
  
    return this;
  }
  
  /**
   * @param {string} name
   */
  unuse(name) {
    delete this._strategies[name];
    return this;
  }

  /**
   * @param {FrameworkConnect} fw
   */
  framework(fw) {
    this._framework = fw;
    return this;
  }

  /**
   * @param {SessionManager} sm 
   */
  sessionManager(sm) {
    this._sm = sm;
    return this;
  }

  /**
   * @param {InitializeOptions} [options]
   */
  initialize(options) {
    options = options ?? {};
    return this._framework.initialize(this, options);
  }

  /**
   * @param {string} strategy 
   * @param {AuthenticateOptions} options 
   * @param {AuthenticateCallback} [callback]
   */
  authenticate(strategy, options, callback) {
    return this._framework.authenticate({
      passport: this,
      name: strategy,
      options,
      callback,
    });
  }

  /**
   * @param {string} strategy 
   * @param {AuthorizeOptions} options 
   * @param {AuthenticateCallback} [callback]
   */
  authorize(strategy, options, callback) {
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

  /**
   * @param {AuthenticateOptions} options
   */
  session(options) {
    return this.authenticate('session', options);
  }

  /** @type {SerializeUser} */
  serializeUser(...args) {
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
  
      /** @type {(i: number, err?: string, obj?: object) => void} */
      const pass = (i, err, obj) => {
        if (err === 'pass') {
          err = undefined;
        }
  
        if (err || obj || obj === 0) {
          return done(err, obj);
        }
  
        /** @type {SerializeUserA[0] | SerializeUserB[0]} */
        const layer = stack[i];
  
        if (!layer) {
          return done(new Error('Failed to serialize user into session'));
        }
  
        /** @type {SerializeUserCallback} */
        const serialized = (e, o) => pass(i + 1, e, o);
  
        /** @type {(x: SerializeUserA[0] | SerializeUserB[0]) => x is SerializeUserA[0]} */
        const isA = (x) => x.length === 2;
  
        /** @type {(x: SerializeUserA[0] | SerializeUserB[0]) => x is SerializeUserB[0]} */
        const isB = (x) => x.length === 3;

        try {
          if (isB(layer) && req) { // Original code does not check for req being defined
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

  /** @type {DeserializeUser} */
  deserializeUser(...args) {
    if (args.length === 1) {
      this._deserializers.push(args[0]);
      return;
    }

    if(args.length === 2 || args.length === 3) {
      const serializedUser = args[0];
      const req = args.length === 3 ? args[1] : undefined;
      const done = args.length === 3 ? args[2] : args[1];
  
      const stack = this._deserializers;
  
      /** @type {(i: number, err?: string, obj?: false | Express.User | null | undefined) => void} */
      const pass = (i, err = '', user = undefined) => {
        if ('pass' === err) {
          err = undefined;
        }
  
        if (err || user) {
          return done(err, user ?? undefined); // Undefined is a workaround for typing
        }
  
        if (user === null || user === false) {
          return done(null, false);
        }
  
        /** @type {DeserializeUserA[0] | DeserializeUserB[0]} */
        const layer = stack[i];
  
        if (!layer) {
          return done(new Error('Failed to deserialize user out of session'));
        }
  
        /** @type {DeserializeUserCallback} */
        const deserialized = (e, u) => pass(i + 1, e, u);

        /** @type {(x: DeserializeUserA[0] | DeserializeUserB[0]) => x is DeserializeUserA[0]} */
        const isA = (x) => x.length === 2;

        /** @type {(x: DeserializeUserA[0] | DeserializeUserB[0]) => x is DeserializeUserB[0]} */
        const isB = (x) => x.length === 3;
  
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

  /** @type {TransformAuthInfo} */
  transformAuthInfo(...args) {
    if (args.length === 1) {
      this._infoTransformers.push(args[0]);
      return;
    }

    if (args.length === 2 || args.length === 3) {
      const info = args[0];
      const req = args.length === 3 ? args[1] : undefined;
      const done = args.length === 3 ? args[2] : args[1];
  
      const stack = this._infoTransformers;
  
      /** @type {(i: number, err?: string, obj?: NonNullable<unknown>) => void} */
      const pass = (i, err, tinfo) => {
        if (err === 'pass') {
          err = undefined;
        }
  
        if (err || tinfo) {
          return done(err, tinfo);
        }
  
        /** @type {TransformAuthInfoA[0] | TransformAuthInfoB[0] | TransformAuthInfoC[0]} */
        const layer = stack[i];
  
        if (!layer) {
          return done(null, info);
        }
  
        /** @type {TransformAuthInfoCallback} */
        const transformed = (e, t) => pass(i + 1, e, t);

        /** @type {(x: TransformAuthInfoA[0] | TransformAuthInfoB[0] | TransformAuthInfoC[0]) => x is TransformAuthInfoA[0]} */
        const isA = (x) => x.length === 1;

        /** @type {(x: TransformAuthInfoA[0] | TransformAuthInfoB[0] | TransformAuthInfoC[0]) => x is TransformAuthInfoB[0]} */
        const isB = (x) => x.length === 2;
      
        /** @type {(x: TransformAuthInfoA[0] | TransformAuthInfoB[0] | TransformAuthInfoC[0]) => x is TransformAuthInfoC[0]} */
        const isC = (x) => x.length === 3;
  
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

  /**
   * @param {string} name 
   */
  _strategy(name) {
    return this._strategies[name];
  }
}

module.exports = Passport;
