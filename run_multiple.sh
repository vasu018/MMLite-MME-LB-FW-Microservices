sudo -v

count=0
lcore=3
num=${1:-1}
for i in $(seq $num)
do
count=$((count+1))
if (( $count % 13 == 1 ))           
then
    lcore=$((lcore+1))
fi
echo $count $lcore
sudo -E xterm -hold -e ./examples/bridge/run.sh $((lcore)) 1 &
sleep 1
done

