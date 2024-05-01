export default class AuthenticationError extends Error {
  status: number;

  constructor(message: string, status: number = 401) {
    super(message);
    // This is required when building for ES5
    Object.setPrototypeOf(this, AuthenticationError.prototype);

    this.status = status;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

module.exports = AuthenticationError;
