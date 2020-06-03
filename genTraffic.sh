#!/bin/bash

for i in `shuf -n 100 ./testurls.txt`; do echo $i; curl -s $i -o /tmp/gt.out; sleep 1; done
