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
#include "lb.h"

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "chash"

//#define LOGS  1

#define DEFAULT_SLICEID 1 /* If SLICEID is 0 send it to this */
#define SLICE_NUM_SVC 3 /* tells the number of different types of MME's used  */

#define REPLICAS  160
#define MAX_HOSTS 100
#define MAX_SLICEID 100
#define MAX_INT 0xFFFFFFFF
#define RAND_CONN_TEST 1
#define CONN_TEST 0
#define MAX_CONNECTIONS 1000
#define EXP_START_PORT    2355
#define EXP_STOP_PORT     2356

#define JENKINS_ONE_TIME_HASH 1
#define SDBM_HASH 0
#define FNV1A_HASH 0
#define DJB2_HASH 0
#define MURMUR3_HASH 0
#define BOB_JENKINS_HASH 0

#if BOB_JENKINS_HASH
#define mix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}
#endif

int cmpchash (const void * a, const void * b);
float get_hash(char *key, size_t len);
float get_host_hash(int host_id, int replica_id);
int get_host(char* key, size_t len);
void add_host(int host_id);
void remove_host(int host_id);
void add_n_hosts(int n);
static void *s_mem(char * data, int size );


char chash_ring[] = "hash_ring";

typedef struct {
        float hash;
        int host;
} hostringpt_t;

typedef struct {
        int active_hosts;
        hostringpt_t hostringpts[MAX_HOSTS * REPLICAS];
} hostring_t;

hostring_t hostring;


enum msg_type {
	MSG_ATTACH = 0,
	MSG_SERVICE = 1,
	MSG_DETACH = 2

};

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;


typedef struct traffic {
	uint32_t enb_ue_s1ap_id;
	uint8_t dest;
	struct traffic * next;
} traffic_t;

traffic_t  *traffic_log=NULL;
traffic_t *cur_traffic_log=NULL;

int ring[MAX_HOSTS];

int host_count;

int ring_counter;


/* number of package between each print */
static uint32_t print_delay = 1000000;


static uint32_t destination;

int cmpchash (const void * a, const void * b) {
        float l = ((const hostringpt_t*)a)->hash;
        float r = ((const hostringpt_t*)b)->hash;
        if (l > r)
                return 1;
        else if (l < r)
                return -1;
	else 
		return 0;
}

static void *s_mem(char * data, int size ){

	void * ret = rte_zmalloc("KVS", size, 0);
	if(!ret)
		return NULL;
	memcpy(ret, data, size);
	return ret;
}

float get_hash(char *key, size_t len) {
#if JENKINS_ONE_TIME_HASH
        uint32_t hash, i;
        for(hash = i = 0; i < len; ++i)
        {
                hash += key[i];
                hash += (hash << 10);
                hash ^= (hash >> 6);
        }
        hash += (hash << 3);
        hash ^= (hash >> 11);
        hash += (hash << 15);
        return ((float)(hash) );

#endif

#if FNV1A_HASH
        unsigned char *p = key;
        unsigned h = 0x811c9dc5;
        int i;

        for ( i = 0; i < len; i++ )
                h = ( h ^ p[i] ) * 0x01000193;

        return (float)h;
#endif

#if DJB2_HASH
        unsigned long hash = 5381;
        unsigned char *str = key;
        int c;

        while (c = *str++)
            hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

        return (float)hash;
#endif

#if SDBM_HASH
        unsigned char *str = key;
        unsigned long hash = 0;
        int c;

        while (c = *str++)
            hash = c + (hash << 6) + (hash << 16) - hash;

        return (float)hash;
#endif

#if MURMUR3_HASH
  uint32_t h = rand();
  if (len > 3) {
    const uint32_t* key_x4 = ( uint32_t*) key;
    size_t i = len >> 2;
    do {
      uint32_t k = *key_x4++;
      k *= 0xcc9e2d51;
      k = (k << 15) | (k >> 17);
      k *= 0x1b873593;
      h ^= k;
      h = (h << 13) | (h >> 19);
      h = (h * 5) + 0xe6546b64;
    } while (--i);
    key = (const uint8_t*) key_x4;
  }
  if (len & 3) {
    size_t i = len & 3;
    uint32_t k = 0;
    key = &key[i - 1];
    do {
      k <<= 8;
      k |= *key--;
    } while (--i);
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
  }
  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;

#endif

#if BOB_JENKINS_HASH
   uint32_t initval = rand();
   uint32_t a,b,c,length;
   unsigned char *k = key;

   /* Set up the internal state */
   length = len;
   a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
   c = initval;         /* the previous hash value */

   /*---------------------------------------- handle most of the key */
   while (length >= 12)
   {
      a += (k[0] +((uint32_t)k[1]<<8) +((uint32_t)k[2]<<16) +((uint32_t)k[3]<<24));
      b += (k[4] +((uint32_t)k[5]<<8) +((uint32_t)k[6]<<16) +((uint32_t)k[7]<<24));
      c += (k[8] +((uint32_t)k[9]<<8) +((uint32_t)k[10]<<16)+((uint32_t)k[11]<<24));
      mix(a,b,c);
      k += 12; len -= 12;
   }

   /*------------------------------------- handle the last 11 bytes */
   c += length;
   switch(length)              /* all the case statements fall through */
   {
   case 11: c+=((uint32_t)k[10]<<24);
   case 10: c+=((uint32_t)k[9]<<16);
   case 9 : c+=((uint32_t)k[8]<<8);
      /* the first byte of c is reserved for the length */
   case 8 : b+=((uint32_t)k[7]<<24);
   case 7 : b+=((uint32_t)k[6]<<16);
   case 6 : b+=((uint32_t)k[5]<<8);
   case 5 : b+=k[4];
   case 4 : a+=((uint32_t)k[3]<<24);
   case 3 : a+=((uint32_t)k[2]<<16);
   case 2 : a+=((uint32_t)k[1]<<8);
   case 1 : a+=k[0];
     /* case 0: nothing left to add */
   }
   mix(a,b,c);
   /*-------------------------------------------- report the result */
   return c;

#endif

}

float get_host_hash(int host_id, int replica_id) {
        char key[10];
        sprintf(key, "%d %d", host_id, replica_id);
        return get_hash(key, 16);
		
}

int get_host(char* key, size_t len) {
        float mhash = get_hash(key, len);
		hostringpt_t *h=(hostringpt_t *)kvs_get(chash_ring, mhash);
		if(h!=NULL)
			return h->host;
        //printf("hash = %f\n", mhash);
        int first_host_ind = (MAX_HOSTS - hostring.active_hosts) * REPLICAS;
/*
        int i;

        for (i = first_host_ind; i < MAX_HOSTS * REPLICAS; i++) {
                if(hostring.hostringpts[i].hash > mhash ) {
                        return hostring.hostringpts[i].host;
                }
        }
        return hostring.hostringpts[first_host_ind].host;
*/
        int highp = MAX_HOSTS * REPLICAS;
        int lowp = (MAX_HOSTS - hostring.active_hosts) * REPLICAS, midp;
		int host;
        float midval, midval1;
        while ( 1 )
        {
        midp = (int)( ( lowp+highp ) / 2 );

        if ( midp == MAX_HOSTS * REPLICAS )
		{
                host=hostring.hostringpts[first_host_ind].host; // if at the end, roll back to zeroth
				break;
		}
        midval = hostring.hostringpts[midp].hash;
        midval1 = midp == first_host_ind ? 0 : hostring.hostringpts[midp-1].hash;
		//printf("lowp %d highp %d midp %d\n",lowp,highp,midp);
		//printf("midval %f midval1 %f\n",midval,midval1);

        if ( mhash <= midval && mhash > midval1 )
		{
			//printf("host %d\n",hostring.hostringpts[midp].host);
                host = hostring.hostringpts[midp].host;
				break;
		}

        if ( midval < mhash )
                lowp = midp + 1;
        else
                highp = midp - 1;

        if ( lowp > highp )
		{
			//printf("host %d\n",hostring.hostringpts[first_host_ind].host);
                host= hostring.hostringpts[first_host_ind].host;
				break;
		}
        }
		hostringpt_t hmem;
		hmem.host=host;
		hmem.hash=mhash;
		kvs_set(chash_ring, mhash, s_mem((char *)&hmem, sizeof(hostringpt_t)));
		return host;
}

/*host ids start with 1. Host id 0 means no host*/
void add_host(int host_id) {
        int i;
        int replica_id = 0;
		printf("adding replicas for host id = %d\n",host_id);

        for (i = 0; i < MAX_HOSTS * REPLICAS && replica_id < REPLICAS; i++) {
                if(hostring.hostringpts[i].host == 0) {
                        hostring.hostringpts[i].host = host_id;
                        hostring.hostringpts[i].hash = get_host_hash(host_id,replica_id);
                        hostringpt_t hmem;
						hmem.host=host_id;
						hmem.hash=hostring.hostringpts[i].hash;
						kvs_set(chash_ring, hostring.hostringpts[i].hash, s_mem((char *)&hmem, sizeof(hostringpt_t)));
						replica_id++;
                }
        }
        hostring.active_hosts++;
        qsort( (void*) &hostring.hostringpts[0],  MAX_HOSTS * REPLICAS, sizeof( hostringpt_t ), cmpchash );
		printf("total hosts=%d\n",hostring.active_hosts);
		printf("total replicas added=%d\n",replica_id);
		printf("i value: %d\n",i);
}

void remove_host(int host_id) {
        int i;
        for (i = 0; i < MAX_HOSTS * REPLICAS; i++) {
                if(hostring.hostringpts[i].host == host_id) {
                        hostring.hostringpts[i].host = 0;
                        hostring.hostringpts[i].hash = 0;
                }
        }
        hostring.active_hosts--;
        qsort( (void*) &hostring.hostringpts[0],  MAX_HOSTS * REPLICAS, sizeof( hostringpt_t ), cmpchash );
}


void add_n_hosts(int n) {
        int i;
        for (i = 0; i < n; i++) {
                add_host(ring[i]);
        }
//      qsort( (void*) &hostring[0],  MAX_HOSTS * REPLICAS, sizeof( hostring_t ), cmpchash );
}

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

int exp_ctr=0;

static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
	struct tcp_hdr* p_tcp_hdr= NULL;
	struct udp_hdr* p_udp_hdr= NULL;
	if((pkt == NULL)||(meta == NULL))
		return 0;
	
	struct ipv4_hdr* ipv4 = onvm_pkt_ipv4_hdr(pkt);
	if((pkt == NULL)||(meta == NULL))
		return 0;
	uint8_t ip_options_length = 0;
	if((ipv4->version_ihl&0x0f) > 5)
		ip_options_length = (((ipv4->version_ihl) & 0x0f) - 5) * 32;
	
	p_tcp_hdr = mme_pkt_tcp_hdr(pkt);
	p_udp_hdr = mme_pkt_udp_hdr(pkt);
	/*TODO: This needs to be changed to ONVM_NF_ACTION_OUT  */
    meta->action = ONVM_NF_ACTION_OUT;
	uint8_t *pkt_data;
	pkt_identifier_t    *pkt_identifier;
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
		printf("port %d\n",p_udp_hdr->dst_port);
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
#ifdef LOGS
		printf("s1ap parsing failed\n");
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
				
		//char key[100];
		//sprintf(key,"%lu",enb_ue_s1ap_id);
		//uint16_t key = enb_ue_s1ap_id;
		uint64_t key = *(uint64_t *)(pkt_data + 4 + sizeof(int));
		pkt_identifier->MMEID = get_host((char *)&key,16);
		if(procedure_code==12)
		{
			//printf("CHASH~%d\n",pkt_identifier->MMEID);
			cur_traffic_log->enb_ue_s1ap_id=enb_ue_s1ap_id;
			cur_traffic_log->dest=pkt_identifier->MMEID;
			cur_traffic_log->next=(traffic_t *)malloc(sizeof(traffic_t));
			cur_traffic_log=cur_traffic_log->next;
		}

	}
	
        if (pkt->port == 0) {
                meta->destination = 1;
        }
        else {
                meta->destination = 0;
        }

        return 0;
}

int init_ring_chash(void)
{
	host_count = 0;
	ring_counter = 0;
	memset(ring,0,sizeof(int)*MAX_HOSTS);
	FILE *fp;
	fp = fopen("mme_info.dat","r");
	//int t=0;
	//int slice_id;
	//ini i=0;
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

        const char *progname = argv[0];

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

		init_ring_chash();
		kvs_hash_init(chash_ring);
		add_n_hosts(host_count);
        onvm_nflib_run(nf_info, &packet_handler);
		

        printf("If we reach here, program is ending\n");
        return 0;
}
