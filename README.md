# ais-auth

This repo is my work in progress about authenticating AIS using Certificateless crypto.

## Requirements 

- gr-ais_simulator (https://github.com/Mictronics/ais-simulator)
- PBC lib (https://crypto.stanford.edu/pbc/)
- OpenSSL dev 

## TODO

- [ ] Send data over AIS (for now data is sent using ZMQ)
- [ ] Create simulation mode (using ZMQ ?)
- [ ] Add timestamp and timestamp verification
- [ ] Add message-signature linkage
- [ ] Support multiple KGCs
- [ ] Support batch signing of messages
- [ ] Automatic registration of public key if signature is valid
- [ ] Send public key every x time/messages
- [ ] Replay scenario from AIS log
- [ ] Add flexibility to support various schemes easily

## How it works

The sources are in the src/ folder.
The .c files do the crypto work using PBC lib, and the .py files handle communcications and all the pther stuff.<br>
The messages to sign and verify, and the IDs are given to ./client and ./KGC programms by .py files in bytes (sha256). The other parameters (PBC element_t usually) are given in b64 format, ascii encoded.