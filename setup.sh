#!/bin/sh
cd ../../
mkdir -p build/lib
clang -o build/lib/neat.o -c NeatCrypto/c/neat.c
ar rcs build/lib/libneat.a build/lib/neat.o
rm build/lib/neat.o
cd _corral/github_com_vijayee_NeatCrypto/
