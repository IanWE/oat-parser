#!/bin/bash

for i in `ls testfile/arm64/`
do
  ./oatparser --read-file=testfile/arm64/$i --m=0-0-0
done
