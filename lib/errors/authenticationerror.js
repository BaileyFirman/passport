class AuthenticationError extends Error {
  /**
   * @param {string} message
   * @param {number} [status=401]
   */
  constructor(message, status = 401) {
    super(message);

    this.name = this.constructor.name;
    this.status = status;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

module.exports = AuthenticationError;
