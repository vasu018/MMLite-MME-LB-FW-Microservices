/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2016 George Washington University
 *            2015-2016 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * speed_tester.c - create pkts and loop through NFs.
 ********************************************************************/

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
//#include <rte_cuckoo_hash.h>
#include "kvs_main.h"
char svc_lt_htable[] = "svc_lt";

#define NF_TAG "speed"

#define NUM_PKTS 128
#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define PKT_READ_SIZE  ((uint16_t)32)
#define SGW_CREATE_SESSION 5
#define SPEED_TESTER_BIT 7

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

int main_keep_running = 1;
static void
handle_signal(int sig) {
        if (sig == SIGINT || sig == SIGTERM) {
                main_keep_running = 0;
        }
}


static int
thread_fn(void *arg){

	if(arg){
		printf("arg is not null\n");
	}

   for (int i = 0;i<15;i++) {

	   RTE_LOG(INFO, APP, "%d\n", i);
	   sleep(1);
   }
   main_keep_running = 0;
return 0;
}

int main(int argc, char *argv[]) {
	int ret;
	unsigned cur_lcore;
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
	void * arg = NULL;
	cur_lcore = rte_lcore_id();
	cur_lcore = rte_get_next_lcore(cur_lcore, 1, 1);
    if (rte_eal_remote_launch(thread_fn, (void *)arg, cur_lcore) == -EBUSY) {
            RTE_LOG(ERR, APP, "Core %d is already busy\n", cur_lcore);
            return -1;
    }
    for (int i = 0;i<15;i++) {

 	   RTE_LOG(INFO, APP, "%d\n", i);
 	   sleep(2);
    }

    while(main_keep_running){

    }

        printf("Ending the program");
        printf("\n");

        return 0;
}
