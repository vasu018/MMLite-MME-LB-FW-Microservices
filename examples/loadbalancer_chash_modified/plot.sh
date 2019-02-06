#!/bin/bash

grep -n exp log.txt | cut -d":" -f1 > exp_start_end.txt

#i=`cat exp_start_end.txt | wc -l`

#exp_count= `expr $i / 2`

i=0
ctr=1
line1=0
line2=0
while read line
do
	i=`expr $i + 1`
	if [ $i -eq 1 ]
	then
		line1=$line
	fi
	if [ $i -eq 2 ]
	then
		line2=$line
		echo "$line1 $line2"
		awk -v s="$line1" -v e="$line2" 'NR>1*s&&NR<1*e' log.txt > exp${ctr}_traffic.txt
		ctr=`expr $ctr + 1` 
		i=0
	fi

done < exp_start_end.txt

ctr=`expr $ctr - 1`

i=1

while [ $i -le $ctr ]
do
	rm exp${i}_stats.dat
	host_count=`head -1 ring_config.dat | grep -o "~" | wc -l`
	j=1
	while [ $j -le $host_count ]
	do
		j=`expr $j + 1`
		host=`head -1 ring_config.dat | cut -d"~" -f $j` 
		traffic_count=`cat exp${i}_traffic.txt | cut -d"~" -f12 | grep $host | wc -l`
		echo "$host~$traffic_count" >> exp${i}_stats.dat
	done
	i=`expr $i + 1`
done

python draw_graph.py
