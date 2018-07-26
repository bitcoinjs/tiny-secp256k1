const tape = require('tape')
const fprivates = require('./fixtures/privates.json')

function test (binding) {
  tape('isPrivate', (t) => {
    fprivates.valid.isPrivate.forEach((f) => {
      const d = Buffer.from(f.d, 'hex')

      t.equal(binding.isPrivate(d), f.expected, `${f.d} is ${f.expected ? 'OK' : 'rejected'}`)
    })

    t.end()
  })

  tape('privateAdd', (t) => {
    fprivates.valid.privateAdd.forEach((f) => {
      const d = Buffer.from(f.d, 'hex')
      const tweak = Buffer.from(f.tweak, 'hex')
      const expected = f.expected ? Buffer.from(f.expected, 'hex') : null
      let description = `${f.d} + ${f.tweak} = ${f.expected ? f.expected : null}`
      if (f.description) description += ` (${f.description})`

      t.same(binding.privateAdd(d, tweak), expected, description)
    })

    fprivates.invalid.privateAdd.forEach((f) => {
      const d = Buffer.from(f.d, 'hex')
      const tweak = Buffer.from(f.tweak, 'hex')

      t.throws(() => {
        binding.privateAdd(d, tweak)
      }, new RegExp(f.exception), `${f.description} throws ${f.exception}`)
    })

    t.end()
  })

  tape('privateSub', (t) => {
    fprivates.valid.privateSub.forEach((f) => {
      const d = Buffer.from(f.d, 'hex')
      const tweak = Buffer.from(f.tweak, 'hex')
      const expected = f.expected ? Buffer.from(f.expected, 'hex') : null
      let description = `${f.d} - ${f.tweak} = ${f.expected ? f.expected : null}`
      if (f.description) description += ` (${f.description})`

      t.same(binding.privateSub(d, tweak), expected, description)
    })

    fprivates.invalid.privateSub.forEach((f) => {
      const d = Buffer.from(f.d, 'hex')
      const tweak = Buffer.from(f.tweak, 'hex')

      t.throws(() => {
        binding.privateSub(d, tweak)
      }, new RegExp(f.exception), `${f.description} throws ${f.exception}`)
    })

    t.end()
  })
}

module.exports = test
