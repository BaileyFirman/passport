/* global describe, it, expect, before */
/* jshint expr: true */

var chai = require('chai')
  , authenticateReal = require('../../lib/framework/middleware/authenticate')
  , Passport = require('../..').Passport;

const authenticate = (passport, name, options, callback) => {
  return authenticateReal({ passport, name, options, callback });
};

describe('middleware/authenticate', function() {
  
  describe('with multiple strategies, the first of which succeeds', function() {
    function StrategyA() {
    }
    StrategyA.prototype.authenticate = function(req) {
      this.success({ username: 'bob-a' });
    };
    
    function StrategyB() {
    }
    StrategyB.prototype.authenticate = function(req) {
      this.success({ username: 'bob-b' });
    };
    
    var passport = new Passport();
    passport.use({
      name: 'a',
      strategy: new StrategyA(),
    });
    passport.use({
      name: 'b',
      strategy: new StrategyB(),
    });
    
    var request, error;

    before(function(done) {
      chai.connect.use(authenticate(passport, ['a', 'b']))
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
    
    it('should not error', function() {
      expect(error).to.be.undefined;
    });
    
    it('should set user', function() {
      expect(request.user).to.be.an('object');
      expect(request.user.username).to.equal('bob-a');
    });
  });
  
  describe('with multiple strategies, the second of which succeeds', function() {
    function StrategyA() {
    }
    StrategyA.prototype.authenticate = function(req) {
      this.fail('A challenge');
    };
    
    function StrategyB() {
    }
    StrategyB.prototype.authenticate = function(req) {
      this.success({ username: 'bob-b' });
    };
    
    var passport = new Passport();
    passport.use({
      name: 'a',
      strategy: new StrategyA(),
    });
    passport.use({
      name: 'b',
      strategy: new StrategyB(),
    });
    
    var request, error;

    before(function(done) {
      chai.connect.use(authenticate(passport, ['a', 'b']))
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
    
    it('should not error', function() {
      expect(error).to.be.undefined;
    });
    
    it('should set user', function() {
      expect(request.user).to.be.an('object');
      expect(request.user.username).to.equal('bob-b');
    });
  });
  
});
