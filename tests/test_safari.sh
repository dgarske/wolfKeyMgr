#!/bin/bash

# run from wolfKeyMgr root directory
cp ./tests/test_safari.vault ./tests/test_safari.vault.orig
./src/wolfkeymgr -v ./tests/test_safari.vault &
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\nError starting key manager" && exit 1

sleep 1
./examples/middlebox/decrypt ./tests/test_safari.pcapng https://localhost:8119
RESULT=$?

pkill -TERM wolfkeymgr
sleep 1
rm -f ./tests/test_safari.vault
mv ./tests/test_safari.vault.orig ./tests/test_safari.vault

exit 0
