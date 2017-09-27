#!/bin/sh

set -eu

glob=$*
if [ -z "$glob" ]; then
  glob="test/remote/account_create_tests.js"
fi

./scripts/gen_keys.js
./scripts/gen_vapid_keys.js
./scripts/mocha-coverage.js -R dot $glob
grunt eslint copyright
