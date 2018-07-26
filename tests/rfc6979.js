const tape = require('tape')
const createHash = require('create-hash')
const fixtures = require('./fixtures/rfc6979')
const rfc6979 = require('../rfc6979')
const ecc = require('../')

fixtures.forEach((f) => {
  tape('RFC6979', (t) => {
    t.plan(3)

    const message = Buffer.from(f.message, 'utf8')
    const m = createHash('sha256').update(message).digest()
    const d = Buffer.from(f.d, 'hex')

    let i = 0
    rfc6979(m, d, function (k) {
      if (i === 0) t.equal(k.toString('hex'), f.k0, message + ' (k0)')
      if (i === 1) t.equal(k.toString('hex'), f.k1, message + ' (k1)')
      if (i === 15) t.equal(k.toString('hex'), f.k15, message + ' (k15)')
      if (i > 15) return true
      ++i
      return false
    }, ecc.isPrivate)
  })
})
