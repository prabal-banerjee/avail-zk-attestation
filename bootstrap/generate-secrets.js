const crypto = require("crypto")
const buildEddsa = require("circomlibjs").buildEddsa
const fs = require('fs')

async function generate (validatorCount) {
  eddsa = await buildEddsa()

  var validatorSet = []

  for (var i=0; i<validatorCount; i++) {
    var prvKey = new Uint8Array(Buffer.from(crypto.randomBytes(32)))
    var pubKey = eddsa.prv2pub(prvKey)
    var weight = crypto.randomInt(1,11)

    validatorSet.push({
      sk: prvKey,
      pk: pubKey,
      weight: weight
    })
  }
  return validatorSet
}

async function main () {
  try {
    validatorCount = parseInt(process.argv[2])
    if (isNaN(validatorCount) || validatorCount < 1 || validatorCount > 5) {
      console.log('Allowed validator count between 1 and 5')
      process.exit(1)
    }
    // console.log('All good!')
    var validatorSet = await generate(validatorCount)
    console.log(validatorSet)
  } catch (e) {
    console.log('Need validator count as command line argument.')
    console.log(e)
  }

  for (var i=0; i<validatorCount; i++) {
    dir = '../validators/validator' + i.toString()
    if (!fs.existsSync(dir)){
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(dir + '/keystore', validatorSet[i].sk.toString());
  }

  var sanitizedValSet = validatorSet.map(function (obj) {
    delete obj['sk']
    obj['pk'] = [obj['pk'][0].toString(), obj['pk'][1].toString()]
    return obj
  })

  fs.writeFileSync('../server/validatorSet.json', JSON.stringify(sanitizedValSet))
}

main()