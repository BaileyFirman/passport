const SessionStrategy = require('./strategies/session');
const SessionManager = require('./sessionmanager');
const FrameworkConnect = require('./framework/connect');

/**
 * @typedef {import('../types').Request} Request
 * @typedef {import('../types').Strategy} Strategy
 * @typedef {import('../types').AuthenticateOptions} AuthenticateOptions
 * @typedef {import('../types').AuthenticateCallback} AuthenticateCallback
 * @typedef {import('../types').InitializeOptions} InitializeOptions
 * @typedef {import('../types').AuthorizeOptions} AuthorizeOptions
 * @typedef {import('../types').TID} TID
 * @typedef {import('../types').InitialInfo} InitialInfo
 */

/**
 * @typedef {(user: Express.User, done: (err: any, id?: TID) => void) => void} SerializeTwo
 * @typedef {(req: Express.Request, user: Express.User, done: (err: any, id?: TID) => void) => void} SerializeThree
 * @typedef {SerializeTwo & SerializeThree} SerializeFn
 * @typedef {{
 *   user: Express.User,
 *   req?: Request,
 *   done: (err: any, serializedUser?: number | NonNullable<unknown>) => any,
 * }} SerializeParams
 * 
 * @typedef {(id: TID, done: (err: any, user?: Express.User | false | null) => void) => void} DeserializeTwo
 * @typedef {(req: Express.Request, id: TID, done: (err: any, user?: Express.User | false | null) => void) => void} DeserializeThree
 * @typedef {DeserializeTwo & DeserializeThree} DeserializeFn
 * @typedef {{
 *   serializedUser: NonNullable<unknown>,
 *   req?: Request,
 *   done: (err: any, user?: Express.User | false) => any,
 * }} DeserializeParams
 * 
 * 
 * @typedef {(info: any, done: (err: any, info: any) => void) => void} TransformOne
 * @typedef {TransformOne} TransformFn
 * @typedef {{
 *   info: unknown,
 *   req?: Request,
 *   done: (err: any, transformedAuthInfo?: InitialInfo | NonNullable<unknown>) => any,
 * }} TransformParams
 */

class Passport {
  constructor() {
    this._key = 'passport';
    /** @type {{ [name: string]: Strategy }} */
    this._strategies = {};
    /** @type {Array<SerializeTwo & SerializeThree>} */
    this._serializers = [];
    /** @type {Array<DeserializeTwo & DeserializeThree>} */
    this._deserializers = [];
    this._infoTransformers = [];
    this._framework = null;

    this
      .framework(new FrameworkConnect())
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

  /**
   * @param {SerializeFn | SerializeParams} serializeArg
   */
  serializeUser(serializeArg) {
    if (typeof serializeArg === 'function') {
      return this._serializers.push(serializeArg);
    }

    const { user, req, done } = serializeArg;

    const stack = this._serializers;

    /** @type {(i: number, err?: string, obj?: object) => void} */
    const pass = (i, err = '', obj = undefined) => {
      if (err === 'pass') {
        err = undefined;
      }

      if (err || obj || obj === 0) {
        return done(err, obj);
      }

      const layer = stack[i];

      if (!layer) {
        return done(new Error('Failed to serialize user into session'));
      }

      /** @type {(e: string, o: object) => void} */
      const serialized = (e, o) => pass(i + 1, e, o);

      try {
        if (layer.length === 3) {
          layer(req, user, serialized);
        } else if(layer.length === 2) {
          layer(user, serialized);
        }
      } catch (e) {
        return done(e);
      }
    }

    pass(0);
  }

  /**
   * @param {DeserializeFn | DeserializeParams} deserializeArg
   */
  deserializeUser(deserializeArg) {
    if (typeof deserializeArg === 'function') {
      return this._deserializers.push(deserializeArg);
    }

    const { serializedUser, req, done } = deserializeArg;

    const stack = this._deserializers;

    /** @type {(i: number, err?: string, obj?: NonNullable<unknown>) => void} */
    function pass(i, err = '', user = undefined) {
      if ('pass' === err) {
        err = undefined;
      }

      if (err || user) {
        return done(err, user);
      }

      if (user === null || user === false) {
        return done(null, false);
      }

      const layer = stack[i];

      if (!layer) {
        return done(new Error('Failed to deserialize user out of session'));
      }

      /** @type {(e: string, u: Express.User) => void} */
      const deserialized = (e, u) => pass(i + 1, e, u);

      try {
        if (layer.length === 3) {
          layer(req, serializedUser, deserialized);
        } else {
          layer(serializedUser, deserialized);
        }
      } catch (e) {
        return done(e);
      }
    }

    pass(0);
  }

   /**
    * @param {TransformFn | TransformParams} transformArg
    */
  transformAuthInfo(transformArg) {
    if (typeof transformArg === 'function') {
      return this._infoTransformers.push(transformArg);
    }

    const { info, req, done } = transformArg;

    const stack = this._infoTransformers;

    /** @type {(i: number, err?: string, obj?: NonNullable<unknown>) => void} */
    const pass = (i, err, tinfo) => {
      if (err === 'pass') {
        err = undefined;
      }

      if (err || tinfo) {
        return done(err, tinfo);
      }

      const layer = stack[i];

      if (!layer) {
        return done(null, info);
      }

      /** @type {(e: string, t: InitialInfo) => void} */
      const transformed = (e, t) => pass(i + 1, e, t);

      try {
        if (layer.length == 1) {
          const t = layer(info);
          transformed(null, t);
        } else if (layer.length == 3) {
          layer(req, info, transformed);
        } else {
          layer(info, transformed);
        }
      } catch (e) {
        return done(e);
      }
    };

    pass(0);
  }

  /**
   * @param {string} name 
   */
  _strategy(name) {
    return this._strategies[name];
  }
}

module.exports = Passport;
