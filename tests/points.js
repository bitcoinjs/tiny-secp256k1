let ecurve = require('../ecurve')
//  let elliptic = require('elliptic') // for reference
let native = require('bindings')('secp256k1')
let tape = require('tape')

let fpoints = require('./fixtures/points.json')

function test (binding) {
  tape('isPoint', (t) => {
    fpoints.valid.isPoint.forEach((f) => {
      let p = Buffer.from(f.P, 'hex')

      t.equal(binding.isPoint(p), f.expected, `${f.P} is ${f.expected ? 'OK' : 'rejected'}`)
    })

    t.end()
  })

  tape('isPointCompressed', (t) => {
    fpoints.valid.isPoint.forEach((f) => {
      if (!f.expected) return
      let p = Buffer.from(f.P, 'hex')
      let e = p.length === 33

      t.equal(binding.isPointCompressed(p), e, `${f.P} is ${e ? 'compressed' : 'uncompressed'}`)
    })

    t.end()
  })

  tape('pointAdd', (t) => {
    fpoints.valid.pointAdd.forEach((f) => {
      let p = Buffer.from(f.P, 'hex')
      let q = Buffer.from(f.Q, 'hex')

      let expected = f.expected ? Buffer.from(f.expected, 'hex') : null
      let description = `${f.P} + ${f.Q} = ${f.expected ? f.expected : null}`
      if (f.description) description += ` (${f.description})`

      t.same(binding.pointAdd(p, q), expected, description)
      if (expected === null) return

      t.same(binding.pointAdd(p, q, true), binding.pointCompress(expected, true), description)
      t.same(binding.pointAdd(p, q, false), binding.pointCompress(expected, false), description)
    })

    fpoints.invalid.pointAdd.forEach((f) => {
      let p = Buffer.from(f.P, 'hex')
      let q = Buffer.from(f.Q, 'hex')

      t.throws(() => {
        binding.pointAdd(p, q)
      }, new RegExp(f.exception), `${f.description} throws ${f.exception}`)
    })

    t.end()
  })

  tape('pointAddScalar', (t) => {
    fpoints.valid.pointAddScalar.forEach((f) => {
      let p = Buffer.from(f.P, 'hex')
      let d = Buffer.from(f.d, 'hex')

      let expected = f.expected ? Buffer.from(f.expected, 'hex') : null
      let description = `${f.P} + ${f.d} = ${f.expected ? f.expected : null}`
      if (f.description) description += ` (${f.description})`

      t.same(binding.pointAddScalar(p, d), expected, description)
      if (expected === null) return

      t.same(binding.pointAddScalar(p, d, true), binding.pointCompress(expected, true), description)
      t.same(binding.pointAddScalar(p, d, false), binding.pointCompress(expected, false), description)
    })

    fpoints.invalid.pointAddScalar.forEach((f) => {
      let p = Buffer.from(f.P, 'hex')
      let d = Buffer.from(f.d, 'hex')

      t.throws(() => {
        binding.pointAddScalar(p, d)
      }, new RegExp(f.exception), `${f.description} throws ${f.exception}`)
    })

    t.end()
  })

  tape('pointCompress', (t) => {
    fpoints.valid.pointCompress.forEach((f) => {
      let p = Buffer.from(f.P, 'hex')
      let expected = f.expected ? Buffer.from(f.expected, 'hex') : null

      t.same(binding.pointCompress(p, f.compress), expected)
    })

    fpoints.invalid.pointCompress.forEach((f) => {
      let p = Buffer.from(f.P, 'hex')

      t.throws(() => {
        binding.pointCompress(p)
      }, new RegExp(f.exception), `${f.description} throws ${f.exception}`)
    })

    t.end()
  })

  tape('pointFromScalar', (t) => {
    fpoints.valid.pointFromScalar.forEach((f) => {
      let d = Buffer.from(f.d, 'hex')

      let expected = f.expected ? Buffer.from(f.expected, 'hex') : null
      let description = `${f.d} * G = ${f.expected ? f.expected : null}`
      if (f.description) description += ` (${f.description})`

      t.same(binding.pointFromScalar(d), expected, description)
      if (expected === null) return

      t.same(binding.pointFromScalar(d, true), binding.pointCompress(expected, true), description)
      t.same(binding.pointFromScalar(d, false), binding.pointCompress(expected, false), description)
    })

    fpoints.invalid.pointFromScalar.forEach((f) => {
      let d = Buffer.from(f.d, 'hex')

      t.throws(() => {
        binding.pointFromScalar(d)
      }, new RegExp(f.exception), `${f.description} throws ${f.exception}`)
    })

    t.end()
  })

  tape('pointMultiply', (t) => {
    fpoints.valid.pointMultiply.forEach((f) => {
      let p = Buffer.from(f.P, 'hex')
      let d = Buffer.from(f.d, 'hex')

      let expected = f.expected ? Buffer.from(f.expected, 'hex') : null
      let description = `${f.P} * ${f.d} = ${f.expected ? f.expected : null}`
      if (f.description) description += ` (${f.description})`

      t.same(binding.pointMultiply(p, d), expected, description)
      if (expected === null) return

      t.same(binding.pointMultiply(p, d, true), binding.pointCompress(expected, true), description)
      t.same(binding.pointMultiply(p, d, false), binding.pointCompress(expected, false), description)
    })

    fpoints.invalid.pointMultiply.forEach((f) => {
      let p = Buffer.from(f.P, 'hex')
      let d = Buffer.from(f.d, 'hex')

      t.throws(() => {
        binding.pointMultiply(p, d)
      }, new RegExp(f.exception), `${f.description} throws ${f.exception}`)
    })

    t.end()
  })
}

test(ecurve)
test(native)
