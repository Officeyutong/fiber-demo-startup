#!/bin/bash
/create-ckb-account.sh
mkdir ckb
echo 12345678 | /ckb-cli account export --lock-arg $(/ckb-cli account list --output-format json | jq -r ".[0].lock_arg") --extended-privkey-path /ckb-key
head -n 1 ./ckb-key > ./ckb/key
FIBER_SECRET_KEY_PASSWORD=12345678 /fnn -c /config.yml -d .
