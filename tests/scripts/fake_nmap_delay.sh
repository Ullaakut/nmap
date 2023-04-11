#!/bin/bash
input=$1
count=0
while IFS= read -r line
do
  echo "$line"
  if [ $count -gt 13 ] && [ $count -lt 23 ]
  then
    sleep 0.1
  fi
  (( count++ ))
done < "$input"
