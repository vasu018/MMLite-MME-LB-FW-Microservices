#!/bin/sh

args=("$@")

name=`echo ${args[0]} | cut -f2 -d"/"`
#pname=`pgrep $name | sed -n '1p'`
pname=$(pgrep -a $name | awk '{print $1}')
file=$(pgrep -a $name | awk '{print $(NF-3)}')
printf -- "process array = %s\n" "${pname[@]}"
printf -- "file-name array = %s\n" "${file[@]}"
read -a file <<< $file

for element in ${pname[@]}
do
	echo "pname: " $element
	echo "writing to file " "logs/""${file[$counter]}"".txt"
	perf stat -e cycles,instructions,task-clock -p $element -o "logs/""${file[$counter]}"".txt" &
	counter=$((counter+1))
done

