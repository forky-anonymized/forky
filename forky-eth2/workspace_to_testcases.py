import os
import shutil
import yaml

# Define directories
working_dir = os.getcwd()
test_cases_dir = os.path.join(working_dir, "test_cases_with_check")
blocks_dir = os.path.join(working_dir, "blocks")
attestations_dir = os.path.join(working_dir, "attestations")
result_dir = os.path.join(working_dir, "result")
anchor_state_path = os.path.join(working_dir, "anchor_state") + "/anchor_state.ssz_snappy"
print(anchor_state_path)
anchor_block_path = os.path.join(working_dir, "anchor_block") + "/anchor_block.ssz_snappy"

# Loop through test case files
for filename in os.listdir(test_cases_dir):
    print(filename)
    # Load YAML file
    with open(os.path.join(test_cases_dir, filename), "r") as f:
        test_case = yaml.safe_load(f)

    # Create new directory for test case
    if not os.path.exists(result_dir):
        os.mkdir(result_dir)
    new_dir = os.path.join(result_dir, filename)
    os.mkdir(new_dir)

    # Find block and attestation files
    block_filenames = []
    attestation_filenames = []
    for item in test_case:
        if isinstance(item, dict):
            if "block" in item:
                block_filenames.append(item["block"])
            elif "attestation" in item:
                attestation_filenames.append(item["attestation"])

    # print(block_filenames, attestation_filenames)

    # Copy self to new directory
    test_path = os.path.join(test_cases_dir, filename)
    if os.path.exists(test_path):
        dst_path = os.path.join(new_dir, "steps.yaml")
        shutil.copy(test_path, dst_path)
    # Copy anchor state to new directory
    if os.path.exists(anchor_state_path):
        shutil.copy2(anchor_state_path, new_dir)
    if os.path.exists(anchor_block_path):
        shutil.copy2(anchor_block_path, new_dir)

    # Copy block files to new directory
    for block_filename in block_filenames:
        file_name = block_filename + ".ssz_snappy"
        # print(file_name)
        block_path = os.path.join(blocks_dir, file_name)
        if os.path.exists(block_path):
            shutil.copy2(block_path, new_dir)

    # Copy attestation files to new directory
    for attestation_filename in attestation_filenames:
        file_name = attestation_filename + ".ssz_snappy"
        # print(file_name)
        attestation_path = os.path.join(attestations_dir, file_name)
        if os.path.exists(attestation_path):
            shutil.copy2(attestation_path, new_dir)
