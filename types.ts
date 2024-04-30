import RequestWrapper from './lib/framework/middleware/http/request';
import SessionManager from './lib/sessionmanager';

export type ExtendedStrategy = import('passport-strategy').Strategy & {
    name?: string;
} & {
    [property: string]: any;
};

export type ExtendedRequest = import('express').Request & {
    _userProperty?: string;
    _sessionManager?: SessionManager;
    flash: (type: string, msg: string) => void;
    session: import('express-session').Session & {
        returnTo?: string;
        messages?: string[];
        [property: string]: any;
    };
    logIn: RequestWrapper['logIn'];
    login: RequestWrapper['logIn'];
    logOut: RequestWrapper['logOut'];
    logout: RequestWrapper['logOut'];
    [property: string]: any;
};

module.exports = {};
