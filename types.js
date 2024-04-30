/**
 * @typedef {import('passport-strategy').Strategy & {
 *   name?: string;
 * } & {
 *   [property: string]: any;
 * }} Strategy
 */

/**
 * @typedef {import('express').Request & {
 *  _userProperty?: string;
 * _sessionManager?: import('./lib/sessionmanager');
 * flash: (type: string, msg: string) => void;
 * session: import('express-session').Session & {
 *   returnTo?: string;
 *   messages?: string[];
 *   [property: string]: any;
 * };
 * logIn: import('./lib/framework/middleware/http/request')['logIn'];
 * login: import('./lib/framework/middleware/http/request')['login'];
 * logOut: import('./lib/framework/middleware/http/request')['logOut'];
 * logout: import('./lib/framework/middleware/http/request')['logout'];
 * [property: string]: any;
 * }} Request
 */

module.exports = {};
