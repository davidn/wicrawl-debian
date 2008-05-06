#!/bin/bash

make="/usr/bin/make"
cvs="/usr/bin/cvs"

cd /home/midnightresearch.com/local/packages/wicrawl/wicrawl
$cvs -q upd -Pd
./configure
$make clean
$make dist

mv wicrawl-cvs.tgz ../

date >> /home/midnightresearch.com/local/packages/wicrawl/wicrawl-cvs-date.txt
