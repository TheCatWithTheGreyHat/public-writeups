#!/bin/sh

echo $FLAG > /tmp/flag.txt
export FLAG=""

LINKER="./lib/ld-linux-x86-64.so.2"
LIB="./lib"

exec $LINKER --library-path $LIB ./chall
