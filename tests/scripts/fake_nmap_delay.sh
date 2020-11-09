#!/bin/bash
input=$1
while IFS= read -r line
do
  echo "$line"
  sleep .5
done < "$input"
