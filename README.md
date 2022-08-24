# Zero-Knowledge based Avail Attestation Bridge

## Idea
The idea is to create a PoC which pushes data root from Avail blocks to Ethereum, along with a ZKP proving that super-majority has signed that root. 

The PoC has the following agents:
- Validator: A listener script runs within validator nodes with access to it's secret key. It listens to finalized blocks and upon receiving it, signs and sends it to the server. 
- Server: The server listens to POST requests made by validators, and upon receiving it verifies signature and saves it into an in-memory datastore. Upon external trigger, it tries to generate a ZK proof and submits it to (mock) Ethereum. 

