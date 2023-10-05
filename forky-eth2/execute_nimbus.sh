#!/bin/bash

WORKDIR=$PWD

mkdir -p ./nimbus-23.5.1/vendor/nim-eth2-scenarios/tests-v1.3.0/mainnet/capella/fork_choice/forky/pyspec_tests
rm -rf ./nimbus-23.5.1/vendor/nim-eth2-scenarios/tests-v1.3.0/mainnet/capella/fork_choice/forky/pyspec_tests/*
cp -r ./testcases/* ./nimbus-23.5.1/vendor/nim-eth2-scenarios/tests-v1.3.0/mainnet/capella/fork_choice/forky/pyspec_tests
cd ./nimbus-23.5.1
make test 2>&1 | tee $WORKDIR/logs_nimbus