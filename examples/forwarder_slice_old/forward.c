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
 * forward.c - an example using onvm. Forwards packets to a DST NF.
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

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>

#include <rte_hash.h>

#include "kvs_main.h"

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "simple_forward"

#define DEFAULT_SLICEID 1 /* If SLICEID is 0 send it to this */
#define SLICE_NUM_SVC 3 /* tells the number of different types of MME's used  */

#define EXP_1_1 0
#define EXP_2 1


enum msg_type {
	MSG_ATTACH = 0,
	MSG_SERVICE = 1,
	MSG_DETACH = 2,
	MSG_PERF_MME = 3
};

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;


static uint32_t destination;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, dst_flag = 0;

        while ((c = getopt(argc, argv, "d:p:")) != -1) {
                switch (c) {
                case 'd':
                        destination = strtoul(optarg, NULL, 10);
                        dst_flag = 1;
                        break;
                case 'p':
                        print_delay = strtoul(optarg, NULL, 10);
                        break;
                case '?':
                        usage(progname);
                        if (optopt == 'd')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (optopt == 'p')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (isprint(optopt))
                                RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                        else
                                RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                        return -1;
                default:
                        usage(progname);
                        return -1;
                }
        }

        if (!dst_flag) {
                RTE_LOG(INFO, APP, "Simple Forward NF requires destination flag -d.\n");
                return -1;
        }

        return optind;
}


static struct udp_hdr*
mme_pkt_udp_hdr(struct rte_mbuf* pkt) {
        struct ipv4_hdr* ipv4 = onvm_pkt_ipv4_hdr(pkt);
	uint8_t ip_options_length = 0;
        if (unlikely(ipv4 == NULL)) {  // Since we aren't dealing with IPv6 packets for now, we can ignore anything that isn't IPv4
                return NULL;
        }

        if (ipv4->next_proto_id != IP_PROTOCOL_UDP) {
                return NULL;
        }
	if((ipv4->version_ihl&0x0f) > 5)
		ip_options_length = (((ipv4->version_ihl) & 0x0f) - 5) * 32;
        uint8_t* pkt_data = rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length;
        return (struct udp_hdr*)pkt_data;
}


static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
	uint8_t slice = DEFAULT_SLICEID;
	struct udp_hdr* p_udp_hdr= NULL;
	int dst = 1;
	if((pkt == NULL)||(meta == NULL))
		return 0;
	p_udp_hdr = mme_pkt_udp_hdr(pkt);

        meta->action = ONVM_NF_ACTION_TONF;
        meta->destination = destination;

	if( p_udp_hdr ) {
		/* TODO: Need to figure out the starting location of the payload what is down is wrong*/
		uint8_t *pkt_data = (uint8_t *)p_udp_hdr + sizeof(struct udp_hdr);
		slice = *(pkt_data + 0);
		/*Fetch message type from the next location */

		uint8_t msg_type = *(pkt_data + 1);

		if(slice == 0){
			/* send the slice to the default slice id*/
			slice = DEFAULT_SLICEID;
		}

#if 0
		if( msg_type == MSG_ATTACH) {
			dst = 1 + (slice -1)  * SLICE_NUM_SVC + 1; 
		} else if ( msg_type == MSG_SERVICE ) {
			dst = 1 + (slice -1)  * SLICE_NUM_SVC + 1; 
		} else if ( msg_type == MSG_DETACH ) {
			dst = 1 + (slice -1)  * SLICE_NUM_SVC + 1; 
		} else {
			 meta->action = ONVM_NF_ACTION_DROP;
		}	
#else 

#if EXP_1_1
	#define STATEFUL 0
		long downtime = (CLOCKS_PER_SEC/1000) * 100;
		clock_t now;
		static clock_t down_end, down_start;
		static int flag, count;
//		printf("sliceid %d\n", slice);
                if( msg_type == MSG_ATTACH) {
                        dst = slice + 1;
                }
		else if ( msg_type == MSG_SERVICE) {
			if(flag != 1) {
				flag = 1;
				down_end = clock() + downtime + (CLOCKS_PER_SEC/1000) * 20;
				down_start = clock() + (CLOCKS_PER_SEC/1000) * 20;
				count = 0;
			}
			now = clock();
			dst = slice + 1;
//			if( (now > down_start) && (now - down_start < downtime))
			//printf("now : %ld down_start : %ld down_end : %ld \n", now, down_start, down_end);
			if (now <  down_end && now > down_start && dst == 3)
			{
//				printf("MME down %d \n", count);
				count++;
	#if STATEFUL
				meta->action = ONVM_NF_ACTION_DROP;
	#else
				dst = 2;
	#endif
			}
		}
                else {
                         meta->action = ONVM_NF_ACTION_DROP;
                }
//		printf("dst sid %d\n", dst);
#endif

#if EXP_2
	#define STATEFUL 0
	#if STATEFUL
		if( msg_type == MSG_ATTACH || msg_type == MSG_SERVICE) {
			dst = slice + 1;
		}
		else {
                         meta->action = ONVM_NF_ACTION_DROP;
                }
	#else
                if( msg_type == MSG_ATTACH) {
                        dst = 2;
                } else if ( msg_type == MSG_SERVICE ) {
                        dst = 3;
                } else if ( msg_type == MSG_DETACH ) {
                        dst = 1 + (slice -1)  * SLICE_NUM_SVC + 1;
                } else {
                         meta->action = ONVM_NF_ACTION_DROP;
                }
	#endif/*STATEFUL*/
#endif/*EXP_2*/
#endif
		//printf("sliceid:%x msg_type:%x dst:%d\n",slice,msg_type,dst);
		meta->destination = dst;
		if ( (msg_type == MSG_SERVICE) || (msg_type == MSG_DETACH)) {
			/* write code for validation here */
			
		}

	}
	
        return 0;
}


int main(int argc, char *argv[]) {
        int arg_offset;

        const char *progname = argv[0];

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        onvm_nflib_run(nf_info, &packet_handler);
        printf("If we reach here, program is ending\n");
        return 0;
}
