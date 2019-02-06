#!/bin/bash


SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")


#exec sudo $SCRIPTPATH/build/forward -l $cpu -n 3 --proc-type=secondary -- -r $service $instance -- -d $dst $print
#exec sudo gdb --args $SCRIPTPATH/build/ue_state_logger -l $cpu -n 3 --proc-type=secondary --file-prefix onvm -- -r $service $clientname $instance -- -d $dst $print
#exec sudo $SCRIPTPATH/build/ue_state_client -l $cpu -n 3 --proc-type=secondary --file-prefix onvm -- -r $service $clientname $instance -- -d $dst $print
exec sudo $SCRIPTPATH/build/ue_state_client -n 3 --proc-type=secondary --file-prefix onvm -- 130.245.144.70 $1 $2 $3 
