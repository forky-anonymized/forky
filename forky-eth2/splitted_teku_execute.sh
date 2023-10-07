#!/bin/bash

for i in {0..7}; do
  echo "START GROUP $i"
  source_directory="group$i"
  mv ./splited/$source_directory ./testcases
  echo "START Teku Test for GROUP $i"
  ./generate_teku.sh
  python3 get_fails.py > ./fails$1.txt
  mv ./testcases ./splited/$source_directory
  echo "END Teku Test for GROUP $i"
done
