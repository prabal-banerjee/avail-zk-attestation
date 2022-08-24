const express = require('express')
const buildEddsa = require("circomlibjs").buildEddsa

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
    // console.log(msg, sig, pubkey)
    if (!eddsa.verifyPoseidon(msg, sig, pubkey)) {
      throw new Error('Signature cannot be verified!')
    }
    console.log('Signature verified message received!')

    signStruct = {
      pubkey: [req.body.pubkeyX, req.body.pubkeyY],
      signature: req.body.signature
    }

    // TODO: Protect against data races
    if (msg in inMemoryDB) {
      var val = inMemoryDB[msg]
      val += signStruct
      inMemoryDB[msg] = val
    } else {
      inMemoryDB[msg] = [signStruct]
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

var inMemoryDB = {}
app.listen(8080)
