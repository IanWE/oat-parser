#!/bin/bash

for i in `ls framework/oat/arm64/`
do
  echo $i
  ./oatparser --read-file=framework/oat/arm64/$i --m=0-0-0
done
