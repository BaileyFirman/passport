/* global describe, it, expect, before */
/* jshint expr: true */

var chai = require('chai')
  , authenticateReal = require('../../lib/framework/middleware/authenticate')
  , Passport = require('../..').Passport;

const authenticate = (passport, name, options, callback) => {
  return authenticateReal({ passport, name, options, callback });
};

describe('middleware/authenticate', function() {
  
  it('should be named authenticate', function() {
    expect(authenticate.name).to.equal('authenticate');
  });
  
  describe('with unknown strategy', function() {
    var passport = new Passport();
    
    var request, error;

    before(function(done) {
      chai.connect.use(authenticate(passport, 'foo'))
        .req(function(req) {
          request = req;
          
          req.logIn = function({ user, options, callback }) {
            this.user = user;
            callback();
          };
        })
        .next(function(err) {
          error = err;
          done();
        })
        .dispatch();
    });
    
    it('should error', function() {
      expect(error).to.be.an.instanceOf(Error);
      expect(error.message).to.equal('Unknown authentication strategy "foo"');
    });
    
    it('should not set user', function() {
      expect(request.user).to.be.undefined;
    });
    
    it('should not set authInfo', function() {
      expect(request.authInfo).to.be.undefined;
    });
  });
  
});
