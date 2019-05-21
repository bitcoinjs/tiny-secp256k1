'use strict'

try {
  module.exports = require('tiny-secp256k1-native')
} catch (err) {
  module.exports = require('./js')
}
