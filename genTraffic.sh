#!/bin/bash

for i in `shuf -n 1000 ./testurls.txt`; do curl -s $i -o /tmp/gt.out; sleep $(( $RANDOM % 6 )); done
