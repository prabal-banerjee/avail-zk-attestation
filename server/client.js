const axios = require('axios')
const crypto = require("crypto")

const buildEddsa = require("circomlibjs").buildEddsa
const buildBabyjub = require("circomlibjs").buildBabyjub
const buildPoseidon = require("circomlibjs").buildPoseidon

async function doPostRequest() {
  eddsa = await buildEddsa()
  babyJub = await buildBabyjub()
  poseidon = await buildPoseidon()
  F = poseidon.F

  var msg = poseidon([0])
  var prvKey = crypto.randomBytes(32)
  var pubKey = eddsa.prv2pub(prvKey)
  var signature = eddsa.signPoseidon(prvKey, msg)
  // console.log(msg, signature, pubKey)

  const res = await axios.post('http://localhost:8080/sign', {
    signature: signature.S.toString(),
    R8x: signature.R8[0].toString(),
    R8y: signature.R8[1].toString(),
    message: msg.toString(),
    pubkeyX: pubKey[0].toString(),
    pubkeyY: pubKey[1].toString(),
  });

  let data = res.data
  console.log(data)
}

doPostRequest()
doPostRequest()
doPostRequest()
doPostRequest()
doPostRequest()
doPostRequest()
doPostRequest()
doPostRequest()