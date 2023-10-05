# forky-eth2

# How to Generate Testcases with Fuzzer
```
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup install nightly
rustup default nightly
cargo install cargo-fuzz

# install LLVM
curl -LO https://apt.llvm.org/llvm.sh 
chmod +x llvm.sh 
./llvm.sh 13 # Note that you must run with llvm13

# Run Lighthouse Fork-choice fuzzer
cd fuzz-lighthouse     
ENABLE_EPOCH_MUTATION=0 cargo fuzz run fc ./workspace/corpus/ --  -max_len=200000 -detect_leaks=0 -ignore_timeouts=1 -reduce_inputs=0 -rss_limit_mb=8192
```

# How to Run Lighthouse Consensus Spec Test
```
# Put testcase in lighthouse/testing/ef_tests/forky/pyspec_tests/

# Run 
# This takes time as cargo test builds lighthouse from the scratch
./execute_lighthouse.sh

# Results can be found in forky-eth2/logs_lighthouse

```

# How to Run Nimbus Consensus Spec Test
```
# Build
cd nimbus-23.5.1
mv tmp.git .git
make consensus_spec_tests_mainnet -j4
cd ..

# Put testcases in forky-eth2/testcases

# Run
./execute_nimbus.sh

# Results can be found in forky-eth2/logs_nimbus

```

# How to Run Prysm Consensus Spec Test
```
# Install Go
sudo apt install golang-go 

# Install Bazel
sudo apt install bazel-6.2.1

# Build
cd prysm-4.0.7
bazel build //... --build_tag_filters=forky
cd ..

# Put testcases in forky-eth2/testcases

# Run
./execute_prysm.sh

# Results (FAILED) can be found in forky-eth2/logs_prysm

```

# How to Run Teku Consensus Spec Test
```
# Install SDK Manager
curl -s "https://get.sdkman.io" | bash  

# Install Gradle
sdk install gradle 7.6.1

# Put testcases in forky-eth2/testcases

# Generate testcase classes
./generate_teku.sh

# Run
cd ./teku-23.6.2/eth-reference-tests
gradle referenceTest
cd ../..

# Results can be found in forky-eth2/teku-23.6.2/eth-reference-tests/build/reports/tests/referenceTest

```
