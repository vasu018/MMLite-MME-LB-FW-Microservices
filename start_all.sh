#!/bin/bash


# aux | grep -ie onvm | awk ’{print $2}’ | xargs sudo kill -9

sudo rm *.log

echo "soumya" |  nohup examples/forwarder_slice_lb/go.sh 5 1 2 &

echo "soumya" | nohup examples/mme_bypass_hss_sgw/go.sh 6 4 1 -k mme1 > mme1.log &

echo "soumya" | nohup examples/mme_bypass_hss_sgw/go.sh 7 5 1 -k mme2 > mme2.log &


echo "soumya" | nohup examples/mme_bypass_hss_sgw/go.sh 8 6 1 -k mme3 > mme3.log &

echo "soumya" | nohup examples/mme_bypass_hss_sgw/go.sh 9 7 1 -k mme4 > mme4.log &

#echo "soumya" | nohup examples/mme_bypass_hss_sgw/go.sh 11 8 1 -k mme5 > mme5.log &

#nohup xterm  -hold -e "examples/mme_bypass_hss_sgw/go.sh 10 9 1 -k mme6" > mme6.log &
#nohup xterm  -hold -e "examples/mme_bypass_hss_sgw/go.sh 11 10 1 -k mme3" > mme7.log &
#nohup xterm  -hold -e "examples/mme_bypass_hss_sgw/go.sh 7 11 1 -k mme3" > mme8.log &
#nohup xterm  -hold -e "examples/mme_bypass_hss_sgw/go.sh 8 12 1 -k mme3" > mme9.log &
#nohup xterm  -hold -e "examples/mme_bypass_hss_sgw/go.sh 9 13 1 -k mme3" > mme10.log &
#nohup xterm  -hold -e "examples/mme_bypass_hss_sgw/go.sh 10 14 1 -k mme3" > mme11.log &


#nohup xterm  -hold -e "examples/forwarder_hss_sgw/go.sh 4 1 2" &

#nohup xterm  -hold -e "examples/dummyhss/go.sh 5 2 1 -k hss" &

#nohup xterm  -hold -e "examples/dummysgw/go.sh 6 3 1 -k sgw" &
