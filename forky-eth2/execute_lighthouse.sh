#!/bin/bash

WORKDIR=$PWD

rm -rf ./lighthouse/testing/ef_tests/forky/pyspec_tests/
mkdir -p ./lighthouse/testing/ef_tests/forky/pyspec_tests/
cp -r ./testcases/* ./lighthouse/testing/ef_tests/forky/pyspec_tests/
cd ./lighthouse
cargo test --release -p ef_tests --features "ef_tests" | tee $WORKDIR/logs_lighthouse