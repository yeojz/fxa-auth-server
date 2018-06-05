/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict'

const assert = require('insist')
const config = require('../../config').getProperties()
const crypto = require('crypto')
const TestServer = require('../test_server')
const Client = require('../client')()
const hkdf = require('../../lib/crypto/hkdf')
const Promise = require('bluebird')
const jose = require('node-jose')

describe('remote recovery keys', function () {
  this.timeout(10000)

  let server, client, email
  const password = '(-.-)Zzz...'

  let recoveryKeyId
  let recoveryData
  let keys
  let keystore

  function createRecoveryKey(uid, kB) {
    const recoveryCode = crypto.randomBytes(16)

    return Promise.all([
      hkdf(recoveryCode, uid, 'fxa recovery fingerprint', 16),
      hkdf(recoveryCode, uid, 'fxa recovery encrypt key', 32)
    ])
      .spread((recoveryKeyId, recoveryKey) => {
        // RecoveryData = JWE(recover-key, {'alg': 'dir', 'enc': 'A256GCM', 'kid': recoveryKeyId}, kB))
        const props = {
          kid: recoveryKeyId.toString('hex'),
          alg: 'A256GCM',
          use: 'enc'
        }
        return jose.JWK.createKey('oct', 256, props)
          .then((result) => {
            keystore = result
            return jose.JWE.createEncrypt(keystore)
              .update(kB)
              .final()
          })
          .then((result) => {
            return {
              recoveryCode: recoveryCode.toString('hex'),
              recoveryData: JSON.stringify(result),
              recoveryKeyId: recoveryKeyId.toString('hex'),
              recoveryKey: recoveryKey.toString('hex')
            }
          })
      })
  }

  before(() => {
    return TestServer.start(config)
      .then(s => server = s)
  })

  beforeEach(() => {
    email = server.uniqueEmail()
    return Client.createAndVerify(config.publicUrl, email, password, server.mailbox, {keys: true})
      .then((x) => {
        client = x
        assert.ok(client.authAt, 'authAt was set')

        return client.keys()
      })
      .then((result) => {
        keys = result

        return createRecoveryKey(client.uid, keys.kB)
          .then((result) => {
            recoveryKeyId = result.recoveryKeyId
            recoveryData = result.recoveryData
            // Should create recovery key
            return client.createRecoveryKey(result.recoveryKeyId, result.recoveryData)
              .then((res) => assert.ok(res, 'empty response'))
          })
      })
  })

  it('should get recovery key', () => {
    return getAccountResetToken(client, server, email)
      .then(() => client.getRecoveryKey(recoveryKeyId))
      .then((res) => {
        assert.equal(res.recoveryData, recoveryData, 'recoveryData returedn')

        const input = JSON.parse(res.recoveryData)
        return jose.JWE.createDecrypt(keystore.keystore)
          .decrypt(input)
      })
      .then((result) => {
        assert.equal(result.plaintext.toString(), keys.kB, 'kB can be decrypted')
      })
  })

  it('should change password and keep key', () => {
    return getAccountResetToken(client, server, email)
      .then(() => client.getRecoveryKey(recoveryKeyId))
      .then((res) => assert.equal(res.recoveryData, recoveryData, 'recoveryData returned'))
      .then(() => client.resetAccountWithRecoveryKey('newpass', keys.kB, recoveryKeyId, {}, {keys: true}))
      .then((res) => {
        assert.equal(res.uid, client.uid, 'uid returned')
        assert.ok(res.sessionToken, 'sessionToken return')
        return client.keys()
      })
      .then((res) => {
        assert.equal(res.kA, keys.kA, 'kA are equal returned')
        assert.equal(res.kB, keys.kB, 'kB are equal returned')

        // Login with new password and check to see kB hasn't changed
        return Client.login(config.publicUrl, email, 'newpass', {keys: true})
          .then((c) => {
            assert.ok(c.sessionToken, 'sessionToken returned')
            return c.keys()
          })
          .then((res) => {
            assert.equal(res.kA, keys.kA, 'kA are equal returned')
            assert.equal(res.kB, keys.kB, 'kB are equal returned')
          })
      })
  })

  after(() => {
    return TestServer.stop(server)
  })
})

function getAccountResetToken(client, server, email) {
  return client.forgotPassword()
    .then(() => server.mailbox.waitForCode(email))
    .then((code) => client.verifyPasswordResetCode(code))
}
