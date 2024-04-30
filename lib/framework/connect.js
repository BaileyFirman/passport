const initialize = require('./middleware/initialize');
const authenticate = require('./middleware/authenticate');

class FrameworkConnect {
  constructor() {
    this.initialize = initialize;
    this.authenticate = authenticate;
    this.authorize = authenticate;
  }
}

module.exports = FrameworkConnect;
