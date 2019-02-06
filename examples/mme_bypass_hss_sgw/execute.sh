#!/bin/sh

args=("$@")

name=`echo ${args[0]} | cut -f2 -d"/"`
pname=`pgrep $name | sed -n '1p'`
echo "pid for" $name "is:" $pname

file=${args[1]}

echo "writing to file " $file
echo "pname: " $pname

perf stat -p $pname -o $file

