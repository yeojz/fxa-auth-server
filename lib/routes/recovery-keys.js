/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict'

const errors = require('../error')
const isA = require('joi')
const random = require('../crypto/random')
const requestHelper = require('../routes/utils/request_helper')
const validators = require('./validators')
const HEX_STRING = validators.HEX_STRING

module.exports = (log, db, Password, verifierVersion, customs) => {
  return [
    {
      method: 'POST',
      path: '/recoveryKeys',
      config: {
        auth: {
          strategy: 'sessionToken'
        },
        validate: {
          payload: {
            recoveryKeyId: isA.string().max(32).required(),
            recoveryData: isA.string().max(1024).required()
          }
        }
      },
      handler(request, reply) {
        log.begin('createRecoveryKey', request)

        const uid = request.auth.credentials.uid
        const sessionToken = request.auth.credentials
        const {recoveryKeyId, recoveryData} = request.payload

        customs.check(request, 'createRecoveryKey')
          .then(createRecoveryKey)
          .then(emitMetrics)
          .then(() => reply({}), reply)

        function createRecoveryKey() {
          if (sessionToken.tokenVerificationId) {
            throw errors.unverifiedSession()
          }

          return db.createRecoveryKey(uid, recoveryKeyId, recoveryData)
        }

        function emitMetrics() {
          log.info({
            op: 'account.recoveryKey.created',
            uid
          })

          return request.emitMetricsEvent('recoveryKey.created', {uid})
        }
      }
    },
    {
      method: 'GET',
      path: '/recoveryKeys/{recoveryKeyId}',
      config: {
        auth: {
          strategy: 'accountResetToken'
        },
        validate: {
          params: {
            recoveryKeyId: isA.string().max(32).required()
          }
        }
      },
      handler(request, reply) {
        log.begin('getRecoveryKey', request)

        const uid = request.auth.credentials.uid
        const recoveryKeyId = request.params.recoveryKeyId
        let recoveryData

        customs.check(request, 'getRecoveryKey')
          .then(getRecoveryKey)
          .then(() => reply({recoveryData}), reply)

        function getRecoveryKey() {
          return db.getRecoveryKey(uid, recoveryKeyId)
            .then((res) => recoveryData = res.recoveryData)
        }
      }
    },
    {
      method: 'POST',
      path: '/account/reset/recoveryKeys',
      config: {
        auth: {
          strategy: 'accountResetToken'
        },
        validate: {
          query: {
            keys: isA.boolean().optional()
          },
          payload: {
            authPW: validators.authPW,
            wrapKb: validators.wrapKb,
            recoveryKeyId: isA.string().max(256).regex(HEX_STRING).required()
          }
        }
      },
      handler: function (request, reply) {
        log.begin('Password.changeRecoveryKeys', request)
        const authPW = request.payload.authPW
        const wrapKb = request.payload.wrapKb
        const recoveryKeyId = request.payload.recoveryKeyId
        const uid = request.auth.credentials.uid

        let authSalt, password, verifyHash, sessionToken, keyFetchToken, account

        checkRecoveryKey()
          .then(getAccount)
          .then(passwordReset)
          .then(createSessionToken)
          .then(createKeyFetchToken)
          .then(deleteRecoveryKey)
          .then(createResponse)
          .then(reply, reply)

        function checkRecoveryKey() {
          return db.getRecoveryKey(uid, recoveryKeyId)
        }

        function getAccount() {
          return db.account(uid)
            .then((result) => account = result)
        }

        // Password reset using a recovery key behaves similarly to a password change. The client should have
        // retrieved their original `kB` and rewrapped the kB.
        function passwordReset() {
          return random.hex(32)
            .then(hex => {
              authSalt = hex
              password = new Password(authPW, authSalt, verifierVersion)
              return password.verifyHash()
            })
            .then((hash) => {
              verifyHash = hash
              return password.wrap(wrapKb)
            })
            .then((wrapWrapKb) => {
              return db.resetAccount(
                {uid},
                {
                  verifyHash: verifyHash,
                  authSalt: authSalt,
                  wrapWrapKb: wrapWrapKb,
                  verifierVersion: password.version
                }
              )
            })
        }

        function createSessionToken() {
          const {
            browser: uaBrowser,
            browserVersion: uaBrowserVersion,
            os: uaOS,
            osVersion: uaOSVersion,
            deviceType: uaDeviceType,
            formFactor: uaFormFactor
          } = request.app.ua

          const sessionTokenOptions = {
            uid: account.uid,
            email: account.primaryEmail.email,
            emailCode: account.primaryEmail.emailCode,
            emailVerified: account.primaryEmail.isVerified,
            verifierSetAt: account.verifierSetAt,
            uaBrowser,
            uaBrowserVersion,
            uaOS,
            uaOSVersion,
            uaDeviceType,
            uaFormFactor
          }

          return db.createSessionToken(sessionTokenOptions)
            .then((result) => sessionToken = result)
        }

        function createKeyFetchToken() {
          if (requestHelper.wantsKeys(request)) {
            return db.createKeyFetchToken({
              uid: account.uid,
              kA: account.kA,
              wrapKb: wrapKb,
              emailVerified: account.primaryEmail.isVerified
            })
              .then((result) => keyFetchToken = result)
          }
        }

        function deleteRecoveryKey() {
          return db.deleteRecoveryKey(uid, recoveryKeyId)
        }

        function createResponse() {

          const response = {
            uid: sessionToken.uid,
            sessionToken: sessionToken.data,
            verified: sessionToken.emailVerified,
            authAt: sessionToken.lastAuthAt()
          }

          if (requestHelper.wantsKeys(request)) {
            response.keyFetchToken = keyFetchToken.data
          }

          return response
        }
      }
    }
  ]
}
