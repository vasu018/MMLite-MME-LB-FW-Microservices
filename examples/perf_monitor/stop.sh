#!/bin/sh

args=("$@")

name=`echo ${args[0]} | cut -f2 -d"/"`
file=$(pgrep -a $name | awk '{print $(NF-3)}')
printf -- "file-name array = %s\n" "${file[@]}"
read -a file <<< $file

ps aux | grep -ie "perf stat" | awk '{print $2}' | xargs sudo kill -2

output=""
for element in ${file[@]}
do
#remove commas from output file
	echo "reading file: logs/"$element".txt"
	cycles=$(sed "s/\,//g" logs/"$element".txt| sed -n '6p' | awk '{print $1}')
	instrux=$(sed "s/\,//g" logs/"$element".txt | sed -n '7p' | awk '{print $1}')
	cpu=$(sed "s/\,//g" logs/"$element".txt | sed -n '8p' | awk '{print $(NF-2)}')
	time=$(sed "s/\,//g" logs/"$element".txt | sed -n '10p' | awk '{print $1}')
	output=$output$"$cpu,$time,$instrux,$cycles,"
done
	output=$output$'\n'
	echo $output | tee -a test_values.csv
