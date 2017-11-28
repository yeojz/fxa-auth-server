#!/usr/bin/env node

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict'

if (process.argv.length !== 3) {
  console.log(`Usage: ${process.argv[1]} COUNT`)
  console.log('Note: this script will clobber redis')
  process.exit(1)
}

const assert = require('assert')
const crypto = require('crypto')

const config = require('../config').getProperties()
const log = require('../lib/log')(config.log)
const P = require('../lib/promise')
const tokens = require('../lib/tokens')(log, config)
const unblockCode = require('../lib/crypto/base32')(config.signinUnblock.codeLength)

let db
const dbReady = require('../lib/db')(config, log, tokens, unblockCode).connect(config[config.db.backend])
  .then(result => db = result)


let redis
const redisReady = new P(resolve => {
  const redisModule = require('redis')
  P.promisifyAll(redisModule.RedisClient.prototype)
  P.promisifyAll(redisModule.Multi.prototype)
  redis = redisModule.createClient({
    host: config.redis.host,
    port: config.redis.port,
    prefix: config.redis.sessionsKeyPrefix,
    enable_offline_queue: false
  })
  redis.on('ready', resolve)
})

const timings = []
const count = parseInt(process.argv[2])

P.all([ dbReady, redisReady ])
  .then(() => redis.flushallAsync())
  .then(() => test(0))
  .then(() => {
    console.log('Finished!\n')

    const stats = timings.reduce((stats, timing) => {
      stats.update.aggregate += timing.update
      stats.get.aggregate += timing.get
      return stats
    }, {
      update: {
        aggregate: 0,
        mean: 0,
        median: 0
      },
      get: {
        aggregate: 0,
        mean: 0,
        median: 0
      }
    })

    stats.update.mean = stats.update.aggregate / count
    stats.get.mean = stats.get.aggregate / count

    const medianIndex = Math.ceil(count / 2 - 1)
    timings.sort((lhs, rhs) => rhs.update - lhs.update)
    stats.update.median = timings[medianIndex].update
    timings.sort((lhs, rhs) => rhs.get - lhs.get)
    stats.get.median = timings[medianIndex].get

    console.log('# Timings')
    console.log(`Aggregate update time: ${stats.update.aggregate}`)
    console.log(`Mean update time: ${stats.update.mean}`)
    console.log(`Median update time: ${stats.update.median}`)
    console.log(`Aggregate get time: ${stats.get.aggregate}`)
    console.log(`Mean get time: ${stats.get.mean}`)
    console.log(`Median get time: ${stats.get.median}\n`)

    return redis.infoAsync('memory')
  })
  .then(memoryInfo => {
    console.log(memoryInfo)
    process.exit(0)
  })
  .catch(error => {
    console.log(error.stack)
    process.exit(1)
  })

function test (index) {
  if (index === count) {
    return
  }

  const account = {
    uid: crypto.randomBytes(32).toString('hex'),
    email: `fxa-redis-benchmark-${Date.now()}-${index}@example.com`,
    emailVerified: true,
    verifierVersion: 1,
    verifyHash: crypto.randomBytes(32).toString('hex'),
    authSalt: crypto.randomBytes(32).toString('hex'),
    kA: crypto.randomBytes(32).toString('hex'),
    wrapWrapKb: crypto.randomBytes(32).toString('hex')
  }
  const sessionToken = {
    uid: account.uid,
    id: crypto.randomBytes(32).toString('hex'),
    data: crypto.randomBytes(32).toString('hex'),
    createdAt: Date.now()
  }
  let time

  return db.createAccount(account)
    .then(() => db.createSessionToken(sessionToken))
    .then(() => {
      time = process.hrtime()
      return db.updateSessionToken(Object.assign({
        lastAccessTime: Date.now(),
        uaBrowser: 'Firefox',
        uaBrowserVersion: '57',
        uaOS: 'Mac OS X',
        uaOSVersion: '10.11',
        uaDeviceType: null,
        uaFormFactor: null
      }, sessionToken), P.resolve({
        city: 'Bournemouth',
        state: 'England',
        stateCode: 'ENG',
        country: 'United Kingdom',
        countryCode: 'GB'
      }))
    })
    .then(() => {
      const diff = process.hrtime(time)
      assert(diff[0] === 0)
      timings[index] = {
        update: diff[1]
      }
      time = process.hrtime()
      return db.sessions(account.uid)
    })
    .then(() => {
      const diff = process.hrtime(time)
      assert(diff[0] === 0)
      timings[index].get = diff[1]
    })
    .then(() => test(index + 1, count))
}

