/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const P = require('./../promise')

module.exports = function (log) {

  return function start(messageQueue, push) {

    function handleProfileUpdated(message) {
      let uid

      return new P(resolve => {
        uid = message.uid
        log.info({ op: 'handleProfileUpdated', uid: uid, action: 'notify' })
        resolve(push.notifyProfileUpdated(message.uid))
      })
      .catch(function(err) {
        log.error({ op: 'handleProfileUpdated', uid: uid, action: 'error', err: err, stack: err && err.stack })
      })
      .then(function () {
         // We always delete the message, we are not really mission critical
        log.info({ op: 'handleProfileUpdated', uid: uid, action: 'delete' })
        message.del()
      })
    }

    messageQueue.on('data', handleProfileUpdated)
    messageQueue.start()

    return {
      messageQueue: messageQueue,
      handleProfileUpdated: handleProfileUpdated
    }
  }
}
