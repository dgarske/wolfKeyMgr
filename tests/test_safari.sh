#!/bin/bash

# run from wolfKeyMgr root directory
./src/wolfkeymgr -v ./tests/test_safari.vault &
./examples/middlebox/decrypt ./tests/test_safari.pcapng https://localhost:8119
