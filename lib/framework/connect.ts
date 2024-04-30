import initialize from './middleware/initialize';
import authenticate from './middleware/authenticate';

export default class FrameworkConnect {
  initialize: typeof initialize;
  authenticate: typeof authenticate;
  authorize: typeof authenticate;

  constructor() {
    this.initialize = initialize;
    this.authenticate = authenticate;
    this.authorize = authenticate;
  }
}

module.exports = FrameworkConnect;
