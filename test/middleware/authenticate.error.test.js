/* global describe, it, expect, before */
/* jshint expr: true */

var chai = require('chai')
  , authenticateReal = require('../../lib/framework/middleware/authenticate')
  , Passport = require('../..').Passport;

const authenticate = (passport, name, options, callback) => {
  if(!!passport && !!name && !!options && (!callback)) {
    return authenticateReal({ passport, name, callback: options });
  } else {
    return authenticateReal({ passport, name, options, callback });
  }
};

describe('middleware/authenticate', function() {
  
  describe('error', function() {
    function Strategy() {
    }
    Strategy.prototype.authenticate = function(req) {
      this.error(new Error('something is wrong'));
    };
    
    var passport = new Passport();
    passport.use({
      name: 'error',
      strategy: new Strategy(),
    });
    
    var request, error;

    before(function(done) {
      chai.connect.use(authenticate(passport, 'error'))
        .req(function(req) {
          request = req;
        })
        .next(function(err) {
          error = err;
          done();
        })
        .dispatch();
    });
    
    it('should error', function() {
      expect(error).to.be.an.instanceOf(Error);
      expect(error.message).to.equal('something is wrong');
    });
    
    it('should not set user', function() {
      expect(request.user).to.be.undefined;
    });
  });
  
});
