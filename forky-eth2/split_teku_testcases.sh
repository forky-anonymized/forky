#!/bin/bash

WORKDIR=$PWD

testcases=./testcases/*

rm -rf ./teku-23.6.2/eth-reference-tests/src/referenceTest/generated_tests/tech/pegasys/teku/reference/capella/forky/*
rm -rf ./teku-23.6.2/eth-reference-tests/src/referenceTest/resources/consensus-spec-tests/tests/mainnet/capella/forky/*
mkdir -p ./teku-23.6.2/eth-reference-tests/src/referenceTest/generated_tests/tech/pegasys/teku/reference/capella/forky
mkdir -p ./teku-23.6.2/eth-reference-tests/src/referenceTest/resources/consensus-spec-tests/tests/mainnet/capella/forky/

for testcase in $testcases; do
    testname=$(basename $testcase)
    cp -R $testcase/. ./teku-23.6.2/eth-reference-tests/src/referenceTest/resources/consensus-spec-tests/tests/mainnet/capella/forky/Testcase$testname
    cp ./teku-23.6.2/eth-reference-tests/src/referenceTest/Forky.java ./teku-23.6.2/eth-reference-tests/src/referenceTest/generated_tests/tech/pegasys/teku/reference/capella/forky/Testcase$testname.java
    sed -i "s/PLACEHOLDER/Testcase$testname/g" ./teku-23.6.2/eth-reference-tests/src/referenceTest/generated_tests/tech/pegasys/teku/reference/capella/forky/Testcase$testname.java
done

source_directory="$WORKDIR/teku-23.6.2/eth-reference-tests/src/referenceTest/resources/consensus-spec-tests/tests/mainnet/capella/forky"
target_directory="$WORKDIR/teku-23.6.2/eth-reference-tests/src/referenceTest/resources/consensus-spec-tests/tests/mainnet/capella/forky/splited"

n_group=8

# Create the target directory if it doesn't exist
mkdir -p "$target_directory"

# Counter for the subdirectories
count=0

# Loop through the source directories
find "$source_directory" -maxdepth 1 -type d -print0 | while read -d $'\0' directory; do
    # Increment the counter
    ((count++))

    # Calculate the target subdirectory
    target_subdirectory="$target_directory/group$(( (count) % (n_group) ))"

    # Create the target subdirectory if it doesn't exist
    mkdir -p "$target_subdirectory"

    # Move the source directory to the target subdirectory
    mv "$directory" "$target_subdirectory/"

    # Output progress
    echo "Moved: $directory to $target_subdirectory"

done

echo "Done!"
