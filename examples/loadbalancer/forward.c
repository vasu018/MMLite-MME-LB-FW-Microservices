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
#include <rte_tcp.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include "kvs_main.h"

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "lb.h"

#define NF_TAG "Round_Robin"

//#define LOGS  1
#define MAX_CONNECTIONS 20000
#define MAX_HOSTS 100
#define MAX_SLICEID 100
#define DEFAULT_SLICEID 1 /* If SLICEID is 0 send it to this */
#define SLICE_NUM_SVC 3 /* tells the number of different types of MME's used  */
#define EXP_START_PORT    2355
#define EXP_STOP_PORT     2356

char conn_htable[] = "conn_htbl";

enum msg_type {
	MSG_ATTACH = 0,
	MSG_SERVICE = 1,
	MSG_DETACH = 2

};

int ring[MAX_HOSTS];

int host_count;

int ring_counter;

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;


static uint32_t destination;

/*
 * Print a usage message
 */
 
typedef struct traffic {
	uint32_t enb_ue_s1ap_id;
	uint8_t dest;
	struct traffic * next;
} traffic_t;

traffic_t  *traffic_log=NULL;
traffic_t *cur_traffic_log=NULL;
 
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n\n", progname);
}

typedef struct slice_connection_table {
	uint32_t enb_ue_s1ap_id;
	int host_id;
} slice_conn_table_t;

/*
typedef struct connection_table {
	int conn_count;
	slice_conn_table_t slice_conn_table[MAX_CONNECTIONS];
} conn_table_t;
*/
static void *s_mem(char * data, int size ){

	void * ret = rte_zmalloc("KVS", size, 0);
	if(!ret)
		return NULL;
	memcpy(ret, data, size);
	return ret;
}

int cmp_enb_ue_s1ap_id (const void * a, const void * b) {
        uint32_t l = ((const slice_conn_table_t*)a)->enb_ue_s1ap_id;
        uint32_t r = ((const slice_conn_table_t*)b)->enb_ue_s1ap_id;
        if (l > r)
                return 1;
        else if (l < r)
                return -1;
		else 
		return 0;
}

void add_connection(int slice_id,uint32_t enb_ue_s1ap_id,int host_id)
{
	//printf("adding connection\n");
	
	slice_conn_table_t conn[MAX_SLICEID];
	conn[slice_id].enb_ue_s1ap_id = enb_ue_s1ap_id;
	conn[slice_id].host_id = host_id;
	kvs_set(conn_htable, enb_ue_s1ap_id, s_mem((char *)conn, sizeof(slice_conn_table_t) * MAX_SLICEID));
	//slice_conn_table_t * setconn = kvs_get(conn_htable, enb_ue_s1ap_id);
	
	//printf("connection added succesfully\n");
}

int get_connection(int slice_id,uint32_t enb_ue_s1ap_id)
{
		
		slice_conn_table_t * conn;
		conn = kvs_get(conn_htable, enb_ue_s1ap_id);
		return conn[slice_id].host_id;
		
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

static struct tcp_hdr*
mme_pkt_tcp_hdr(struct rte_mbuf* pkt) {
        struct ipv4_hdr* ipv4 = onvm_pkt_ipv4_hdr(pkt);
	//uint8_t ip_options_length = 0;
        if (unlikely(ipv4 == NULL)) {  // Since we aren't dealing with IPv6 packets for now, we can ignore anything that isn't IPv4
                return NULL;
        }

        if (ipv4->next_proto_id != IP_PROTOCOL_TCP) {
                return NULL;
        }

        uint8_t* pkt_data = rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
		
        return (struct tcp_hdr*)pkt_data;
}

int exp_ctr = 0;

static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
	struct udp_hdr* p_udp_hdr= NULL;
	struct tcp_hdr* p_tcp_hdr= NULL;
	struct ipv4_hdr* ipv4 = onvm_pkt_ipv4_hdr(pkt);
	if((pkt == NULL)||(meta == NULL))
		return 0;
	uint8_t ip_options_length = 0;
	if((ipv4->version_ihl&0x0f) > 5)
		ip_options_length = (((ipv4->version_ihl) & 0x0f) - 5) * 32;
	
	p_udp_hdr = mme_pkt_udp_hdr(pkt);
	
	p_tcp_hdr = mme_pkt_tcp_hdr(pkt);
	
	
	
	/*TODO: This needs to be changed to ONVM_NF_ACTION_OUT  */
	
	uint8_t *pkt_data;
	pkt_identifier_t    *pkt_identifier;
	
    meta->action = ONVM_NF_ACTION_OUT;
    meta->destination = destination;
    //static int count = 0;
	if( p_tcp_hdr  || p_udp_hdr) {
		
		if(p_udp_hdr)
			pkt_data = (uint8_t *)p_udp_hdr + sizeof(struct udp_hdr);
			//pkt_identifier =  (pkt_identifier_t*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(struct udp_hdr));
		else
			pkt_data = (uint8_t *)p_udp_hdr + sizeof(struct tcp_hdr);
			//pkt_identifier =  (pkt_identifier_t*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(struct tcp_hdr));
		pkt_identifier = (pkt_identifier_t *)pkt_data;
		
		uint8_t *s1ap_pkt_data =  rte_pktmbuf_mtod(pkt, uint8_t*) 
								+ sizeof(struct ether_hdr) 
								+ sizeof(struct ipv4_hdr) + ip_options_length + 
								sizeof(pkt_identifier_t) + sizeof(struct udp_hdr);
		uint8_t procedure_code = *(s1ap_pkt_data + 1);
#ifdef LOGS
		printf("procedure code %d\n",procedure_code);
#endif
		if(p_udp_hdr->dst_port==EXP_START_PORT)
		{
			FILE *fp;
			if(exp_ctr==0)
				fp = fopen("log.txt","w");
			else
				fp = fopen("log.txt","a");
			exp_ctr++;
			fprintf(fp,"start exp\n");
			fclose(fp);
			if(traffic_log != NULL)
			{
				while(traffic_log!=cur_traffic_log)
				{
					traffic_t *tmp=traffic_log;
					traffic_log=traffic_log->next;
					free(tmp);
				}
				free(traffic_log);
			}
			traffic_log = (traffic_t *)malloc(sizeof(traffic_t));
			cur_traffic_log = traffic_log;
			//meta->action = ONVM_NF_ACTION_DROP;
			if (pkt->port == 0) {
                meta->destination = 1;
			}
			else {
					meta->destination = 0;
			}
			return 0;
		}
		if(p_udp_hdr->dst_port==EXP_STOP_PORT)
		{
			FILE *fp = fopen("log.txt","a");
			while(traffic_log!=cur_traffic_log)
			{
				traffic_t *tmp=traffic_log;
				fprintf(fp,"%d~%d\n",tmp->enb_ue_s1ap_id,tmp->dest);
				traffic_log=traffic_log->next;
				free(tmp);
			}
			
			free(traffic_log);
			fprintf(fp,"end exp\n");
			fclose(fp);
			//meta->action = ONVM_NF_ACTION_DROP;
			if (pkt->port == 0) {
                meta->destination = 1;
			}
			else {
					meta->destination = 0;
			}
			return 0;
		}
		if(procedure_code<=0)
		{
			//meta->action = ONVM_NF_ACTION_DROP;
			if (pkt->port == 0) {
                meta->destination = 1;
			}
			else {
					meta->destination = 0;
			}
			return 0;
		}
		
		s1ap_packet_type s1ap_packet;
		if(s1ap_packet_parser(pkt, &s1ap_packet)<0)
		{
			pkt_identifier->MMEID = 4;
			if (pkt->port == 0) {
                meta->destination = 1;
			}
			else {
                meta->destination = 0;
			}
			return 0;
		}
		
		
		uint64_t enb_ue_s1ap_id = get_enb_ue_s1ap_id(&s1ap_packet);
		
		if(enb_ue_s1ap_id == 0)
		{
#ifdef LOGS	
			printf("s1ap id 0 encountered...ingnoring!!!!\nport %d\n",pkt->port);
			
#endif
			//meta->action = ONVM_NF_ACTION_DROP;
			if (pkt->port == 0) {
                meta->destination = 1;
			}
			else {
					meta->destination = 0;
			}
			return 0;

		}
		
		
		//uint16_t 	mme_type = pkt_identifier->msg_type;
		uint16_t	slice_id = pkt_identifier->slice_id;
		int			host1;
		uint8_t msg_type = get_msg_type(&s1ap_packet);
#ifdef LOGS	
		printf("::::message_type: %d::::\n",msg_type);
		printf("slice id: %d,enb_ue_s1ap_id %lu\n",slice_id,enb_ue_s1ap_id);
#endif
		
		
		if(msg_type==ATTACH_REQUEST || msg_type==SERVICE_REQUEST || msg_type==DETACH_REQUEST) {
			//In this case we need to select a random host.
			host1 = ring[ring_counter];
			ring_counter = (ring_counter + 1)%host_count;
			pkt_identifier->MMEID = host1;
			add_connection(slice_id,enb_ue_s1ap_id,host1);
			cur_traffic_log->enb_ue_s1ap_id=enb_ue_s1ap_id;
			cur_traffic_log->dest=host1;
			cur_traffic_log->next=(traffic_t *)malloc(sizeof(traffic_t));
			cur_traffic_log=cur_traffic_log->next;
			//printf("ROUND ROBIN::destination: %d\n",host1);
			//meta->destination = host1;

		}
		else {
			host1 = get_connection(slice_id,enb_ue_s1ap_id);
			if(host1>0)
			{
				//meta->destination = conn[slice_id].host_id;
				pkt_identifier->MMEID = host1;
#ifdef LOGS		
				printf("Connection found\n");
				printf("destination:%d\n",pkt_identifier->MMEID);
#endif
			}
			else
			{
#ifdef LOGS
				printf("Connection not found\n");
				//printf("slice id: %d,enb_ue_s1ap_id %lu\n",slice_id,enb_ue_s1ap_id);
#endif
				host1 = ring[ring_counter];
				ring_counter = (ring_counter + 1)%host_count;
				pkt_identifier->MMEID = host1;
				add_connection(slice_id,enb_ue_s1ap_id,host1);
			}
			
		}


		/* Some logic on fetching to set the destination */
//		printf("mme_dst:%d \n",mme_dst);
		
	}
	
        if (pkt->port == 0) {
                meta->destination = 1;
        }
        else {
                meta->destination = 0;
        }
        return 0;
}


int init_ring_round_robin(void)
{
	host_count = 0;
	ring_counter = 0;
	memset(ring,0,sizeof(int)*MAX_HOSTS);
	FILE *fp;
	fp = fopen("mme_info.dat","r");
	//int t=0;
	//int slice_id;
	int i=0;
	char ch[3];
	char c;
	while (1)
	{
		c=fgetc(fp);
		//printf("%c-",c);
		if(c=='\n')
		{
			ring[host_count] = atoi(ch);
			printf("host %d\n",ring[host_count]);
			host_count++;
			i=0;
			//continue;
		}
		else
		{
			ch[i]=c;
			i++;
		}
		if(feof(fp))
		{
			ring[host_count] = atoi(ch);
			printf("host %d\n",ring[host_count]);
			host_count++;
			printf("end of file encountered\n");
			printf("host count %d\n",host_count);
			break;
			
		}
		
	}
	return 0;
}

int main(int argc, char *argv[]) {
        int arg_offset;
		traffic_log = (traffic_t *)malloc(sizeof(traffic_t));
		cur_traffic_log = traffic_log;
		//slice_conn_table_t conn[MAX_SLICEID];

        const char *progname = argv[0];

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }
		init_ring_round_robin();
		kvs_hash_init(conn_htable);
		
		//kvs_set(q_htable, i, s_mem((char *)host_stats, sizeof(stat_t)));
		
        onvm_nflib_run(nf_info, &packet_handler);
        printf("If we reach here, program is ending\n");
        return 0;
}
