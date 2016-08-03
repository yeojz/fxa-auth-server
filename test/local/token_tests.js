/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict'

var crypto = require('crypto')
var hkdf = require('../../lib/crypto/hkdf')
var mocks = require('../mocks')
var P = require('../../lib/promise')
var sinon = require('sinon')
var test = require('../ptaptest')

var Bundle = {
  bundle: sinon.spy(),
  unbundle: sinon.spy()
}
var config = {}
var log = mocks.spyLog()

var Token = require('../../lib/tokens/token')(log, crypto, P, hkdf, Bundle, null, config)

test('Token constructor was exported', function (t) {
  t.equal(typeof Token, 'function', 'Token is function')
  t.equal(Token.name, 'Token', 'function is called Token')
  t.equal(Token.length, 2, 'function expects two arguments')
  t.end()
})

test('Token constructor sets createdAt', function (t) {
  var now = Date.now() - 1
  var token = new Token({}, { createdAt: now })

  t.equal(token.createdAt, now, 'token.createdAt is correct')
  t.end()
})

test('Token constructor does not set createdAt if it is negative', function (t) {
  var notNow = -Date.now()
  var token = new Token({}, { createdAt: notNow })

  t.ok(token.createdAt > 0, 'token.createdAt seems correct')
  t.end()
})

test('Token constructor does not set createdAt if it is in the future', function (t) {
  var notNow = Date.now() + 1000
  var token = new Token({}, { createdAt: notNow })

  t.ok(token.createdAt > 0 && token.createdAt < notNow, 'token.createdAt seems correct')
  t.end()
})

test('Token constructor does not set createdAt in production mode', function (t) {
  config.isProduction = true
  var notNow = Date.now() - 1
  var token = new Token({}, { createdAt: notNow })

  t.ok(token.createdAt > notNow, 'token.createdAt seems correct')
  t.end()

  config.isProduction = undefined
})

