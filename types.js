/**
 * @typedef {import('passport-strategy').Strategy & {
 *   name?: string;
 * }} Strategy
 */

/**
 * @typedef {import('express').Request & {
 *  _userProperty?: string;
 * _sessionManager?: import('./lib/sessionmanager');
 * flash: (type: string, msg: string) => void;
 * logIn: import('./lib/framework/middleware/http/request')['logIn'];
 * login: import('./lib/framework/middleware/http/request')['login'];
 * logOut: import('./lib/framework/middleware/http/request')['logOut'];
 * logout: import('./lib/framework/middleware/http/request')['logout'];
 * session: import('express-session').Session & {
 *   returnTo?: string;
 *   messages?: string[];
 * };
 * }} Request
 */

/**
 * @typedef {{
*   authInfo?: boolean,
*   assignProperty?: string,
*   failureFlash?: string | boolean | { type: string; message: string; },
*   failureMessage?: string | boolean,
*   failureRedirect?: string,
*   failWithError?: boolean,
*   keepSessionInfo?: boolean,
*   session?: boolean,
*   scope?: string | string[],
*   successFlash?: string | boolean | { type: string; message: string; },
*   successMessage?: string | boolean,
*   successRedirect?: string,
*   successReturnToOrRedirect?: string,
*   state?: string,
*   pauseStream?: boolean,
*   userProperty?: string,
*   passReqToCallback?: boolean,
*   prompt?: string
* }} AuthenticateOptions
*/

/**
 * @typedef {(
*   err: any,
*   user?: Express.User | false | null,
*   info?: object | string | Array<string | undefined>,
*   status?: number | Array<number | undefined>
* ) => any} AuthenticateCallback
*/

/**
 * @typedef {AuthenticateOptions} AuthorizeOptions
*/

/**
 * @typedef {{
 *   userProperty?: string,
 *   compat?: boolean
 * }} InitializeOptions
*/

/**
 * @typedef {{
 *   pauseStream: boolean,
 * }} SessionOptions
 * 
 * @typedef {{
 *   key: string,
 * }} SessionStrategyOptions
 */

/**
 * @typedef {any} TID
 * @typedef {unknown} InitialInfo
 */

/**
 * @typedef {{
 *   keepSessionInfo?: boolean;
 * }} LogoutOptions
 * 
 * @typedef {{
 *   keepSessionInfo?: boolean;
 *   session?: boolean;    
 * }} LoginOptions
 */

module.exports = {};
