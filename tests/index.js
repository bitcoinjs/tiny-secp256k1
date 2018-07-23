let ecurve = require('../ecurve')

require('./ecdsa')(ecurve)
require('./privates')(ecurve)
require('./points')(ecurve)

try {
  let native = require('bindings')('secp256k1')
  require('./ecdsa')(native)
  require('./privates')(native)
  require('./points')(native)
} catch (e) {
  console.warn('Could not test NATIVE bindings')
}
