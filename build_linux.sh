#!/usr/bin/bash

rm -rf linux
mkdir linux
cd linux
cmake -D__LINUX__=1 -DCMAKE_BUILD_TYPE=Release .. 
make -j8
cd ..

