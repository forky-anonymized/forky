#!/bin/bash

WORKDIR=$PWD

rm -rf ./prysm-4.0.7/bazel-bin/testing/spectest/mainnet/capella/forkchoice/go_default_test_/go_default_test.runfiles/prysm/testing/spectest/mainnet/capella/forkchoice/go_default_test_/tests/mainnet/capella/fork_choice/forky/pyspec_tests
mkdir -p ./prysm-4.0.7/bazel-bin/testing/spectest/mainnet/capella/forkchoice/go_default_test_/go_default_test.runfiles/prysm/testing/spectest/mainnet/capella/forkchoice/go_default_test_/tests/mainnet/capella/fork_choice/forky/pyspec_tests
cp -r ./testcases/* ./prysm-4.0.7/bazel-bin/testing/spectest/mainnet/capella/forkchoice/go_default_test_/go_default_test.runfiles/prysm/testing/spectest/mainnet/capella/forkchoice/go_default_test_/tests/mainnet/capella/fork_choice/forky/pyspec_tests
cd ./prysm-4.0.7/bazel-bin/testing/spectest/mainnet/capella/forkchoice/go_default_test_/go_default_test.runfiles/prysm/testing/spectest/mainnet/capella/forkchoice/go_default_test_/
./go_default_test 2>&1 | tee $WORKDIR/logs_prysm