#!/bin/bash
WORKDIR=$PWD
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
