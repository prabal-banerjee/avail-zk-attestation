const express = require('express')
const buildEddsa = require("circomlibjs").buildEddsa
const wasm_tester = require("circom_tester").wasm
const buildBabyjub = require("circomlibjs").buildBabyjub
const buildPoseidon = require("circomlibjs").buildPoseidon

const app = express()
app.use(express.json()) 

app.post('/sign', async function(req, res) {
  // console.log(req.body)

  try {
    // assert that it is a signed message
    eddsa = await buildEddsa()
    var sig = {
      S: BigInt(req.body.signature),
      R8: [
        new Uint8Array(Buffer.from(JSON.parse("[" + req.body.R8x + "]"))),
        new Uint8Array(Buffer.from(JSON.parse("[" + req.body.R8y + "]")))
      ]
    }
    var pubkey = [
      new Uint8Array(Buffer.from(JSON.parse("[" + req.body.pubkeyX + "]"))),
      new Uint8Array(Buffer.from(JSON.parse("[" + req.body.pubkeyY + "]")))
    ]
    var msg = new Uint8Array(Buffer.from(JSON.parse("[" + req.body.message + "]")))
    var blockNumber = req.body.blockNumber
    // console.log(msg, sig, pubkey)
    if (!eddsa.verifyPoseidon(msg, sig, pubkey)) {
      throw new Error('Signature cannot be verified!')
    }
    console.log('Signature verified message received for block number ', req.body.blockNumber)

    signStruct = {
      msg: req.body.message,
      pubkey: [req.body.pubkeyX, req.body.pubkeyY],
      S: req.body.signature,
      R8: [req.body.R8x, req.body.R8y]
    }

    // TODO: Protect against data races
    if (blockNumber in inMemoryDB) {
      var val = inMemoryDB[blockNumber]
      val.push(signStruct)
      inMemoryDB[blockNumber] = val
    } else {
      inMemoryDB[blockNumber] = [signStruct]
    }

    res.send('Signature verified and stored successfully!')

  } catch (e) {
    console.log('Error occurred!\n', e)
    res.send(e)
  }
})

app.get('/', function(req, res) {
  res.json(inMemoryDB)
})

app.get('/proof', async function(req, res) {
  var blockNumber = req.query.blockNumber
  if (blockNumber === undefined || !(blockNumber in inMemoryDB)) {
    res.send('Bad block number')
    return
  }
  
  eddsa = await buildEddsa()
  babyJub = await buildBabyjub()
  poseidon = await buildPoseidon()
  F = poseidon.F
  circuit = await wasm_tester('../circuits/attestation.circom')

  var validatorSet = []
  var validatorsR8x = []
  var validatorsR8y = []
  var validatorsS = []
  var validatorsIsSigned = []
  var dataRoot = new Uint8Array(Buffer.from(JSON.parse("[" + inMemoryDB[blockNumber][0].msg + "]")))
    
  for (var i=0; i<5; i++) {

    // If part of valdator set
    if (i < inMemoryDB[blockNumber].length) {
      var pubkey = [
        new Uint8Array(Buffer.from(JSON.parse("[" + inMemoryDB[blockNumber][i].pubkey[0] + "]"))),
        new Uint8Array(Buffer.from(JSON.parse("[" + inMemoryDB[blockNumber][i].pubkey[1] + "]")))
      ]
      var R8 = [
        new Uint8Array(Buffer.from(JSON.parse("[" + inMemoryDB[blockNumber][i].R8[0] + "]"))),
        new Uint8Array(Buffer.from(JSON.parse("[" + inMemoryDB[blockNumber][i].R8[1] + "]")))
      ]
      var sig = BigInt(inMemoryDB[blockNumber][i].S)
      var weight = 1  //TODO: fetch from on-disk set

      validatorSet.push(F.toObject(pubkey[0]))
      validatorSet.push(F.toObject(pubkey[1]))
      validatorSet.push(F.toObject(weight))

      validatorsR8x.push(F.toObject(R8[0]))
      validatorsR8y.push(F.toObject(R8[1]))
      validatorsS.push(sig)

      validatorsIsSigned.push(1)

    } else {
      var weight = 1  //TODO: fetch from on-disk set

      validatorSet.push(F.toObject())
      validatorSet.push(F.toObject())
      validatorSet.push(F.toObject(weight))

      validatorsR8x.push(F.toObject())
      validatorsR8y.push(F.toObject())
      validatorsS.push(0)

      validatorsIsSigned.push(0)
    }

  }

  const w = await circuit.calculateWitness({
    validatorSet: validatorSet, 
    dataRoot: F.toObject(dataRoot),
    validatorsR8x: validatorsR8x,
    validatorsR8y: validatorsR8y,
    validatorsS: validatorsS,
    validatorsIsSigned: validatorsIsSigned
  }, true)

  await circuit.checkConstraints(w)

  res.send('Constraints checked!')
})

var inMemoryDB = {}
app.listen(8080)

