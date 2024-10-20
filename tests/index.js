const js = require('../js')

require('./ecdsa')(js)
require('./privates')(js)
require('./points')(js)

try {
  const native = require('../native')
  require('./ecdsa')(native)
  require('./privates')(native)
  require('./points')(native)
} catch (e) {
  console.warn('Could not test NATIVE bindings')
}

// Convert all arguments to Uint8Array and test that it returns equivalent results
const uintWrap = (f) => (...args) => f(...args.map(x => Buffer.isBuffer(x) ? new Uint8Array(x) : x))
const jsUint = Object.fromEntries(Object.entries(js).map(([k, v]) => [k, uintWrap(v)]))

require('./ecdsa')(jsUint)
require('./privates')(jsUint)
require('./points')(jsUint)
