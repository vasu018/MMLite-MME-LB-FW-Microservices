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

#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include <rte_ether.h>
#include <rte_ethdev.h>
#include "mme.h"
#include "mme_context.h"
#define NF_TAG "simple_forward"
#define SPEED_TESTER_BIT 7
#define LOCATION_UPDATE_BIT 6
#define SGW_CREATE_SESSION 5

char IMSI_HTABLE[]={ "imsi_ue_context_htbl"};
char S11_HTABLE[] ={ "tun11_ue_context_htbl"};
char MME_HTABLE[] ={ "mme_ue_s1ap_id_ue_context_htbl"};
char ENB_HTABLE[] ={ "enb_ue_s1ap_id_ue_context_htbl"};
char GUTI_HTABLE[]={ "guti_ue_context_htbl"};

const char* disp_msg[MAX_INDEX] = {
    "ATTACH_REQ_IN",
    "AUTH_PARAMS_OUT",
    "AUTH_PARAMS_IN",
    "AUTH_REQ_OUT",
    "AUTH_RSP_IN",
    "NAS_SECURITY_REQ_OUT",
    "NAS_SECURITY_RSP_IN",
    "LOCATION_UPDATE_REQ_OUT",
    "LOCATION_UPDATE_RSP_IN",
    "CREATE_SESSION_OUT",
    "CREATE_SESSION_IN",
    "ATTACH_ACCEPT_OUT",
    "ATTACH_COMPLETE_IN",
    "MODIFY_BEARER_OUT",
    "MODIFY_BEARER_IN"
};

const char* disp_state[ATTACH_STATES_COUNT] = {
    "ATTACH_REQ RECEIVED",
    "AUTH_PARAMS RECEIVED",
    "AUTH_REQ RECEIVED",
    "NAS_SECURITY_REQ RECEIVED",
    "LOCATION_UPDATE_REQ RECEIVED",
    "CREATE_SESSION_REQ RECEIVED",
    "ATTACH_COMPLETE RECEIVED",
};


/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

TAILQ_HEAD(, pkt_data_s) pkt_data_head;

/* number of package between each print */
static uint32_t print_delay = 1000000;


static uint32_t destination;

int flag = 1;

static 
void sig_handler(int signo)
{
  if (signo == SIGINT) {
    printf("received SIGINT\n");
    flag = 0;
  }
}

static __attribute__((unused)) int print_hex(uint8_t *hex, int num_bytes) 
{
    int i=0;

    while(i+1 < num_bytes) {

        printf("%02X ", hex[i]);

        if (i %8 == 0)
            printf("\n");
        i += 1;
    }
    return 0;

}

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

        while ((c = getopt(argc, argv, "d:p:k:")) != -1) {
            RTE_LOG(INFO, APP, "option given:%c\n",c);
                switch (c) {
                case 'd':
                        destination = strtoul(optarg, NULL, 10);
                        dst_flag = 1;
                        break;
                case 'p':
                        print_delay = strtoul(optarg, NULL, 10);
                        break;
                case 'k':
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




int main(int argc, char *argv[])
{
#if 0
	uint32_t enb_id;
#endif
        int    key=0;
        uint32_t next=0;
	ue_context_t * ue_context = NULL;
        const char *progname = argv[0];
	int i = 0;
	int retval_eal, retval_parse, retval_final, ret;
	double tot_times[MAX_INDEX-2];
	uint8_t fail_counter[ATTACH_STATES_COUNT];
	uint64_t tot_conns = 0;
	double tot_time = 0;

	retval_eal = rte_eal_init(argc, argv);
	if (retval_eal < 0)
		rte_panic("Cannot init EAL\n");


        if (signal(SIGINT, sig_handler) == SIG_ERR) {
            printf("\ncan't catch SIGINT\n");
            return 0;
        }
        opterr = 0; optind = 1;
        if ((retval_parse = onvm_nflib_parse_args(argc - retval_eal, argv+retval_eal)) < 0)
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

        retval_final = (retval_eal + retval_parse) - 1;

        argc -= retval_final;
        argv += retval_final;
        opterr = 0; optind = 1;


        if (parse_app_args(argc, argv, progname) < 0) {
                rte_exit(EXIT_FAILURE, "Invalid 2nd command-line arguments\n");
        }
        
	for(i = 0; i < MAX_INDEX-2; i++)
		tot_times[i] = 0;
	
	for(i = 0; i < ATTACH_STATES_COUNT; i++)
		fail_counter[i] = 0;
	
	printf("\n\n");
	printf("*********************FAILED CONNECTIONS*****************************");
	printf("\n");		
        while((ret=kvs_hash_iterate(ENB_HTABLE, &key,(void*)&ue_context, &next)) >= 0) {
                if(ue_context == NULL)
		{
                        printf("No UE.. ret:%d\n", ret);
		}
                else
		{
			tot_conns++;
                	//printf("Last State of UE %d = %d\n", key, ue_context->conn_state);
			if (ue_context->conn_state < UE_STATE_ATTACH_COMPLETE)
			{
				printf("ERROR for UE with ENB ID %d\n", key);
				printf("Connection state %d\n", ue_context->conn_state);
				fail_counter[ue_context->conn_state]++;
				for(i = 0; i < MAX_INDEX-2; i++)
				{
					printf("Time spent between %s and %s = %lf\n",disp_msg[i], disp_msg[i+1], ((ue_context->time_stamp[i+1]-ue_context->time_stamp[i])*1000)/rte_get_tsc_hz());
				}
			}
			else
			{
				//printf(" %d : %lf\n", key, ue_context->time_stamp[INDEX_ATTACH_COMPLETE_IN]);
				for(i = 0; i < MAX_INDEX-3; i++)
                			tot_times[i] = tot_times[i] + ((ue_context->time_stamp[i+1]-ue_context->time_stamp[i])*1000)/rte_get_tsc_hz();
			}
		}
        }


	for(i = 0; i < ATTACH_STATES_COUNT; i++)
		printf("\nNo of UEs failing after %s state = %d\n", disp_state[i], fail_counter[i]);

	printf("\n\n");
	printf("**************************SUCCESSFUL CONNECTIONS*******************************");
	printf("\n");
        if (tot_conns) {
    	    for(i = 0; i < MAX_INDEX-3; i++){
                printf("Average time spent between %s and %s = %lf\n",disp_msg[i], disp_msg[i+1], tot_times[i]/tot_conns);		
		tot_time = tot_time + tot_times[i]/tot_conns;
	    }
        }
	printf("Average time for complete attach request procedure is %lf\n", tot_time);

        printf("If we reach here, program is ending\n");
        return 0;
}
