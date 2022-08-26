const axios = require('axios')
const crypto = require('crypto')
const fs = require('fs')
const api = require('@polkadot/api')

const buildEddsa = require("circomlibjs").buildEddsa
const buildBabyjub = require("circomlibjs").buildBabyjub
const buildPoseidon = require("circomlibjs").buildPoseidon

async function doPostRequest(msg, number) {
  eddsa = await buildEddsa()
  babyJub = await buildBabyjub()
  poseidon = await buildPoseidon()
  F = poseidon.F

  // var msg = poseidon([0])
  // var prvKey = crypto.randomBytes(32)
  var prvKey = fs.readFileSync('keystore')
  prvKey = new Uint8Array(Buffer.from(JSON.parse("[" + prvKey + "]")))
  var pubKey = eddsa.prv2pub(prvKey)
  var signature = eddsa.signPoseidon(prvKey, msg)
  console.log(msg, signature, pubKey)

  const res = await axios.post('http://localhost:8080/sign', {
    signature: signature.S.toString(),
    R8x: signature.R8[0].toString(),
    R8y: signature.R8[1].toString(),
    message: msg.toString(),
    pubkeyX: pubKey[0].toString(),
    pubkeyY: pubKey[1].toString(),
    blockNumber: number
  });

  let data = res.data
  console.log(data)
}

// doPostRequest()

async function main () {
  const api = await createApi('ws://127.0.0.1:9944')

  const unsubscribe = await api.rpc.chain.subscribeFinalizedHeads((header) => {
    console.log(`Chain is at finalized block: #${header.number}`);

    var dataRoot = header.extrinsicsRoot.dataRoot
    dataRoot = new Uint8Array(Buffer.from(dataRoot))
    doPostRequest(dataRoot, header.number)
  });

}

main()

// Helpers

async function createApi(url) {
    const provider = new api.WsProvider(url)

    // Create the API and wait until ready
    return api.ApiPromise.create({
        provider,
        rpc: {
            kate: {
                queryDataProof: {
                    description: 'Fetch proofs of data inclusion inside data root',
                    params: [
                        {
                            name: 'blockNumber',
                            type: 'u64'
                        },
                        {
                            name: 'txIndex',
                            type: 'u64',
                        }
                    ],
                    type: 'Vec<[u8;32]>'
                },
            },
        },
        types: {
            DataLookup: {
                size: 'u32',
                index: 'Vec<(u32,u32)>'
            },
            KateExtrinsicRoot: {
                hash: 'Hash',
                commitment: 'Vec<u8>',
                rows: 'u16',
                cols: 'u16',
                dataRoot: 'Hash'
            },
            KateHeader: {
                parentHash: 'Hash',
                number: 'Compact<BlockNumber>',
                stateRoot: 'Hash',
                extrinsicsRoot: 'KateExtrinsicRoot',
                digest: 'Digest',
                appDataLookup: 'DataLookup'
            },
            Header: 'KateHeader',
            AppId: 'u32',
        },
        signedExtensions: {
            CheckAppId: {
                extrinsic: {
                    appId: 'u32'
                },
                payload: {}
            },
        },
    })
}
