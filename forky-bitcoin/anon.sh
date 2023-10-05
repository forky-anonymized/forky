#!/bin/bash

find ./ -name 'block.cpp' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'pow.cpp' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'coins.h' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'chain.h' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'validation.h' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'validation.cpp' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'txmempool.h' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'txdb.h' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'chainparams.cpp' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'versionbits.cpp' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'Mutator.h' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'Mutator.h' -exec sed -i"s/${1}/${2}/g" {} \;
find ./ -name 'validationinterface.cpp' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'blockstorage.h' -exec sed -i "s/${1}/${2}/g" {} \;
find ./ -name 'dockerfile' -exec sed -i "s/${1}/${2}/g" {} \;