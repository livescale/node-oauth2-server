'use strict';

/**
 * Module dependencies.
 */

var AbstractGrantType = require('./abstract-grant-type');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidGrantError = require('../errors/invalid-grant-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var is = require('../validator/is');
var util = require('util');

/**
 * Constructor.
 */

function JWTBearerGrantType(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getUser) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getUser()`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  AbstractGrantType.call(this, options);
}

/**
 * Inherit prototype.
 */

util.inherits(JWTBearerGrantType, AbstractGrantType);

/**
 * Retrieve the user from the model using a jwt bearer.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.3.2
 */

JWTBearerGrantType.prototype.handle = function(request, client) {
  if (!request) {
    throw new InvalidArgumentError('Missing parameter: `request`');
  }

  if (!client) {
    throw new InvalidArgumentError('Missing parameter: `client`');
  }

  var scope = this.getScope(request);

  return Promise.bind(this)
    .then(function() {
      return this.getUser(request);
    })
    .then(function(user) {
      return this.saveToken(user, client, scope);
    });
};

/**
 * Get user using an assersion https://datatracker.ietf.org/doc/html/rfc7523#section-2.1
 */

JWTBearerGrantType.prototype.getUser = function(request) {
  if (!request.body.assertion) {
    throw new InvalidRequestError('Missing parameter: `assertion`');
  }

  return promisify(this.model.getUserFromJWT, 1)(request.body.assertion)
    .then((user) => {
      if (!user) {
        throw new InvalidGrantError('Invalid grant: jwt is invalid');
      }

      return user;
    }).catch((e)=>{
      throw new InvalidGrantError(e.message);
    })
};

/**
 * Save token.
 */

JWTBearerGrantType.prototype.saveToken = function(user, client, scope) {
  var fns = [
    this.validateScope(user, client, scope),
    this.generateAccessToken(client, user, scope),
    this.generateRefreshToken(client, user, scope),
    this.getAccessTokenExpiresAt(),
    this.getRefreshTokenExpiresAt()
  ];

  return Promise.all(fns)
    .bind(this)
    .spread(function(scope, accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt) {
      var token = {
        accessToken: accessToken,
        accessTokenExpiresAt: accessTokenExpiresAt,
        refreshToken: refreshToken,
        refreshTokenExpiresAt: refreshTokenExpiresAt,
        scope: scope
      };

      return promisify(this.model.saveToken, 3)(token, client, user);
    });
};

/**
 * Export constructor.
 */

module.exports = JWTBearerGrantType;
