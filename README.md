# ais-auth

This repo is my work in progress about authenticating AIS using Certificateless crypto.

## Requirements 

- gr-ais_simulator (https://github.com/Mictronics/ais-simulator)
- PBC lib (https://crypto.stanford.edu/pbc/)
- OpenSSL dev 

## TODO

- [x] Send data over AIS (for now data is sent using ZMQ)
- [x] Create simulation mode (using ZMQ ?)
- [x] Add timestamp and timestamp verification
- [x] Add message-signature linkage
- [x] Support multiple KGCs
- [x] Replay scenario from AIS log
- [x] Add flexibility to support various schemes easily
- [ ] Add a measurement system
- [x] Sign every x messages for type 1


## How it works

The sources are in the src/ folder.