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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_ether.h>

#include <rte_hash.h>
#include <rte_malloc.h>

#include "kvs_main.h"
#include "cJSON.h"

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "lb.h"

#define NF_TAG "simple_forward"

#define DEFAULT_SLICEID 1 /* If SLICEID is 0 send it to this */
#define SLICE_NUM_SVC 3 /* tells the number of different types of MME's used  */

#define EXP_START_PORT    2355
#define EXP_STOP_PORT     2356

#define VNODES  160
#define MAX_HOSTS 100
#define MAX_SLICEID 100
#define MAX_INT 0xFFFFFFFF
#define RAND_CONN_TEST 1
#define CONN_TEST 0
#define MAX_SLICES 100

#define JENKINS_ONE_TIME_HASH 1
#define SDBM_HASH 0
#define FNV1A_HASH 0
#define DJB2_HASH 0
#define MURMUR3_HASH 0
#define BOB_JENKINS_HASH 0

//#define LOGS 1

#define MAX_CONNECTIONS 2000000





char q_htable[] = "queue_htbl";
char conn_htable[] = "conn_htbl";
char chash_ring[] = "hash_ring";


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
int get_host_slice(char* key, size_t len, int sliceid);
//int get_host_slice(char* key, size_t len);
void add_host_slice(int host_id, int sliceid);
void remove_host_slice(int host_id, int sliceid);
//void add_n_hosts_slice(int n, int sliceid);
void add_n_hosts_slice(int n);
int slice_aware_get_host(uint16_t sliceid, uint64_t key);


typedef struct {
        float hash;
        int host;
} hostringpt_t;

typedef struct {
        int active_hosts;
        hostringpt_t hostringpts[MAX_HOSTS * VNODES];
} hostring_t;

hostring_t hostring[100];

typedef struct slice_connection_table {
	uint32_t enb_ue_s1ap_id;
	int host_id;
} slice_conn_table_t;

typedef struct connection_table {
	int conn_count;
	slice_conn_table_t slice_conn_table[MAX_CONNECTIONS];
} conn_table_t;


typedef struct stats {
	int queue_status;
	float cpu;
}stat_t;

typedef struct proc_stats {
	char msg_type[10];
	uint8_t slo;
	uint32_t enb_ue_s1ap_id;
	uint8_t host[3];
	float latency[3];
	float cpu[3];
	uint8_t dest;
	uint8_t violation;
	struct proc_stats *next;
} proc_stat_t;

proc_stat_t *stat_log=NULL;
proc_stat_t *cur_stat_log=NULL;

//stat_t host_stats[MAX_HOSTS];

enum msg_type {
	MSG_ATTACH = 0,
	MSG_SERVICE = 1,
	MSG_DETACH = 2
};

int ring[3][MAX_HOSTS];
int all_hosts[MAX_HOSTS];

int chosen_hosts[3];

pthread_mutex_t lock;

#define T_ATTACH 1.3
#define T_SERVICE 1.3
#define T_DETACH 1
#define T_DEFAULT 2
#define ATTACH_MSG_COUNT 4
#define SERVICE_MSG_COUNT 4
#define DETACH_MSG_COUNT 2
#define DEFAULT_MSG_COUNT 2
#define T_SLO_0 3
#define T_SLO_1 3
#define T_SLO_2 3


float get_latency(int host,int msg_type)
{
	float latency = 0;
	//pthread_mutex_lock(&lock);
	stat_t *stat = (stat_t *) kvs_get(q_htable, host);
	int q = stat->queue_status;
	float cpu = stat->cpu;
	//pthread_mutex_unlock(&lock);
	//printf("host %d queue %d cpu %f\n",host,stat->queue_status,stat->cpu);
	switch(msg_type)
	{
	case ATTACH_REQUEST:
	
		if(cpu == 0)
			latency = 2 * T_ATTACH;
		else
			latency = (q * 100 / cpu + 1) * T_ATTACH;
		break;
	case SERVICE_REQUEST:
	
		if(cpu == 0)
			latency = 2 * T_SERVICE;
		else
			latency = (q * 100 / cpu + 1) * T_SERVICE;
		break;
	case DETACH_REQUEST:
	
		if(cpu == 0)
			latency = 2 * T_DETACH;
		else
		latency = (q * 100 / cpu + 1) * T_DETACH;
		break;
	default:
	
		if(cpu == 0)
			latency = 2 * T_DEFAULT;
		else
			latency = (q * 100 / cpu + 1) * T_DEFAULT;
	
	}
	return latency;
}

int get_viable_host(int slice_id,int msg_type)
{
	/*
	if(msg_type==ATTACH_REQUEST)
		printf("Get viable ATTACH~");
	if(msg_type==SERVICE_REQUEST)
		printf("Get viable SERVICE~");
	if(msg_type==DETACH_REQUEST)
		printf("Get viable DETACH~");
	*/
	int host = 0;
	float max_latency = 0;
	float min_latency = INT_MAX;
	float max_cpu_usage = 0;
	int second_host = 0;
	int tslo = 0;
	if(slice_id == 0)
		tslo = T_SLO_0;
	else if(slice_id == 1)
		tslo = T_SLO_1;
	else if(slice_id == 2)
		tslo = T_SLO_2;
	//printf("%d~",tslo);
	cur_stat_log->slo=tslo;
	//pthread_mutex_lock(&lock);
	for(int i = 0;i<3;i++)
	{
		float latency = get_latency(chosen_hosts[i],msg_type) + 1;
		cur_stat_log->host[i]=chosen_hosts[i];
		cur_stat_log->latency[i]=latency;
		
		stat_t *stat = (stat_t *) kvs_get(q_htable, chosen_hosts[i]);
		float cpu_usage = 100 - stat->cpu;
		
		cur_stat_log->cpu[i]=cpu_usage;
		
		//printf("%d~%f~%f~",chosen_hosts[i],latency,cpu_usage);
		//int qsize = stat->queue_status;
		if(latency <= tslo)
		{
			if(latency > max_latency)
			{
				host = chosen_hosts[i];
				max_latency = latency;
				max_cpu_usage = cpu_usage;
			}
			else if(latency == max_latency)
			{
				if(cpu_usage > max_cpu_usage)
				{
					host = chosen_hosts[i];
					max_latency = latency;
					max_cpu_usage = cpu_usage;
				}
			}
		}
		if(latency < min_latency)
		{
			min_latency = latency;
			second_host = chosen_hosts[i];
		}
	}
	//pthread_mutex_unlock(&lock);
	if(host == 0)
	{
		cur_stat_log->violation=1;
		//printf("SLO violation encountered!!\n");
		//printf("%d~slo violation\n",second_host);
		cur_stat_log->dest=second_host;
		return second_host;
	}
	cur_stat_log->violation=0;
	cur_stat_log->dest=host;
	//printf("%d~no slo violation\n",host);
	return host;
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

static void *s_mem(char * data, int size ){

	void * ret = rte_zmalloc("KVS", size, 0);
	if(!ret)
		return NULL;
	memcpy(ret, data, size);
	return ret;
}

void add_connection(int slice_id,uint32_t enb_ue_s1ap_id,int host_id)
{

#ifdef LOGS	
	printf("adding connection\n");
#endif
	
	slice_conn_table_t conn[MAX_SLICEID];
	conn[slice_id].enb_ue_s1ap_id = enb_ue_s1ap_id;
	conn[slice_id].host_id = host_id;
	kvs_set(conn_htable, enb_ue_s1ap_id, s_mem((char *)conn, sizeof(slice_conn_table_t) * MAX_SLICEID));
}

int get_connection(int slice_id,uint32_t enb_ue_s1ap_id)
{
		
		slice_conn_table_t * conn;
		conn = kvs_get(conn_htable, enb_ue_s1ap_id);
		return conn[slice_id].host_id;
			
}

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

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
/*
int get_host_slice(char* key, size_t len)
{
	float mhash = get_hash(key, len);
	hostringpt_t *h=(hostringpt_t *)kvs_get(chash_ring, mhash);
	while(h==NULL)
	{
		mhash++;
		h=(hostringpt_t *)kvs_get(chash_ring, mhash);
	}
		
	return h->host;
}
*/

int get_host_slice(char* key, size_t len, int slice_id) {
        float mhash = get_hash(key, len);
		hostringpt_t *h=(hostringpt_t *)kvs_get(chash_ring, mhash);
		if(h!=NULL)
			return h->host;

        int first_host_ind = (MAX_HOSTS - hostring[slice_id].active_hosts) * VNODES;

#ifdef LOGS
        printf("hash = %f\n", mhash);
#endif		

        int highp = MAX_HOSTS * VNODES;
        int lowp = (MAX_HOSTS - hostring[slice_id].active_hosts) * VNODES, midp;
		//int start = lowp;
		//int end = highp;
		int host;
        float midval, midval1;
        while ( 1 )
        {
#ifdef LOGS
        //printf("highp = %d\n", highp);
		//printf("lowp = %d\n", lowp);
#endif
			midp = (int)( ( lowp+highp ) / 2 );
	
			if ( midp == MAX_HOSTS * VNODES )
			{
				host=hostring[slice_id].hostringpts[first_host_ind].host; // if at the end, roll back to zeroth
				break;
			}
			midval = hostring[slice_id].hostringpts[midp].hash;
			midval1 = midp == first_host_ind ? 0 : hostring[slice_id].hostringpts[midp-1].hash;
	
			if ( mhash <= midval && mhash > midval1 )
			{
					host= hostring[slice_id].hostringpts[midp].host;
					break;
			}
	
			if ( midval < mhash )
					lowp = midp + 1;
			else
					highp = midp - 1;
	
			if ( lowp > highp )
			{
					host= hostring[slice_id].hostringpts[first_host_ind].host;
					break;
			}
        }
		hostringpt_t hmem;
		hmem.host=host;
		hmem.hash=mhash;
		kvs_set(chash_ring, mhash, s_mem((char *)&hmem, sizeof(hostringpt_t)));
		return host;
}


int slice_aware_get_host(uint16_t sliceid, uint64_t key) {
	
	int primary_host = get_host_slice((char *)&key, 16, sliceid);
	//int primary_host = get_host_slice((char *)&key, 16);
	chosen_hosts[0] = primary_host;
	int i;
	for(i=0;i<MAX_HOSTS;i++)
	{
		if(ring[sliceid][i]==primary_host)
			break;
	}
	for(int j=1;j<3;j++)
	{
		if(ring[sliceid][(i+1)%MAX_HOSTS]!=0)
		{
			chosen_hosts[j] = ring[sliceid][(i+1)%MAX_HOSTS];
			i++;
		}
		else
		{
			i=0;
			chosen_hosts[j] = ring[sliceid][i];
			//i++;
		}
	}

	return primary_host;

}

/*host ids start with 1. Host id 0 means no host*/
/*
void add_host_slice(int host_id, int slice_id) {
        int i;
        int replica_id = 0;

#ifdef LOGS
		
		printf("adding replicas for host id = %d, slice id = %d\n",host_id,slice_id);
		
#endif
        for (i = 0; i < MAX_HOSTS * VNODES && replica_id < VNODES; i++) {
                if(hostring[slice_id].hostringpts[i].host == 0) {
                	hostring[slice_id].hostringpts[i].host = host_id;
                	hostring[slice_id].hostringpts[i].hash = get_host_hash(host_id,replica_id);
                        replica_id++;
                }
        }

        hostring[slice_id].active_hosts++;

        qsort( (void*) &hostring[slice_id].hostringpts[0],  MAX_HOSTS * VNODES, sizeof( hostringpt_t ), cmpchash );
#ifdef LOGS		
		printf("total hosts=%d\n",hostring[slice_id].active_hosts);
		printf("total replicas added=%d\n",replica_id);
		printf("i value: %d\n",i);
#endif
}
*/


void add_host_slice(int host_id, int slice_id) {
        int i;
        int replica_id = 0;

#ifdef LOGS
		
		printf("adding replicas for host id = %d, slice id = %d\n",host_id,slice_id);
		
#endif
        for (i = 0; i < MAX_HOSTS * VNODES && replica_id < VNODES; i++) {
                if(hostring[slice_id].hostringpts[i].host == 0) {
                	hostring[slice_id].hostringpts[i].host = host_id;
                	hostring[slice_id].hostringpts[i].hash = get_host_hash(host_id,replica_id);
					hostringpt_t hmem;
					hmem.host=host_id;
					hmem.hash=hostring[slice_id].hostringpts[i].hash;
					kvs_set(chash_ring, hostring[slice_id].hostringpts[i].hash, s_mem((char *)&hmem, sizeof(hostringpt_t)));
                        replica_id++;
                }
        }
		hostring[slice_id].active_hosts++;

        qsort( (void*) &hostring[slice_id].hostringpts[0],  MAX_HOSTS * VNODES, sizeof( hostringpt_t ), cmpchash );
		
#ifdef LOGS		
		printf("total hosts=%d\n",hostring[slice_id].active_hosts);
		printf("total replicas added=%d\n",replica_id);
		printf("i value: %d\n",i);
#endif
}

void remove_host_slice(int host_id, int slice_id) {
        int i;
        for (i = 0; i < MAX_HOSTS * VNODES; i++) {
                if(hostring[slice_id].hostringpts[i].host == host_id) {
                	hostring[slice_id].hostringpts[i].host = 0;
                	hostring[slice_id].hostringpts[i].hash = 0;
                }
        }
        hostring[slice_id].active_hosts--;
        qsort( (void*) &hostring[slice_id].hostringpts[0],  MAX_HOSTS * VNODES, sizeof( hostringpt_t ), cmpchash );
}


void add_n_hosts_slice(int slice_id) {
        int i;
        for (i = 0; i < MAX_HOSTS; i++) {
				if(ring[slice_id][i]==0)
					break;
                add_host_slice(ring[slice_id][i], slice_id);
        }
//      qsort( (void*) &hostring[0],  MAX_HOSTS * VNODES, sizeof( hostring_t ), cmpchash );
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
        uint8_t* pkt_data = rte_pktmbuf_mtod(pkt, uint8_t*) 
							+ sizeof(struct ether_hdr) 
							+ sizeof(struct ipv4_hdr) + ip_options_length;
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
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) 
{
	struct tcp_hdr* p_tcp_hdr= NULL;
	struct udp_hdr* p_udp_hdr= NULL;
	struct ipv4_hdr* ipv4 = onvm_pkt_ipv4_hdr(pkt);
	if((pkt == NULL)||(meta == NULL))
		return 0;
	
	uint8_t ip_options_length = 0;
	if((ipv4->version_ihl&0x0f) > 5)
		ip_options_length = (((ipv4->version_ihl) & 0x0f) - 5) * 32;
	
	p_tcp_hdr = mme_pkt_tcp_hdr(pkt);
	p_udp_hdr = mme_pkt_udp_hdr(pkt);
	
	//printf("source port %d\n",p_udp_hdr->src_port);
	
	
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
		printf("procedure code %d port: %d\n",procedure_code,p_udp_hdr->dst_port);
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
			if(stat_log != NULL)
			{
				while(stat_log!=cur_stat_log)
				{
					proc_stat_t *tmp=stat_log;
					stat_log=stat_log->next;
					free(tmp);
				}
				free(stat_log);
			}
			stat_log = (proc_stat_t *)malloc(sizeof(proc_stat_t));
			cur_stat_log=stat_log;
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
			while(stat_log!=cur_stat_log)
			{
				proc_stat_t *tmp=stat_log;
				fprintf(fp,"%s~%d~%d~%f~%f~%d~%f~%f~%d~%f~%f~%d~%d~%d\n",stat_log->msg_type,stat_log->slo,
																	stat_log->host[0],stat_log->latency[0],stat_log->cpu[0],
																	stat_log->host[1],stat_log->latency[1],stat_log->cpu[1],
																	stat_log->host[2],stat_log->latency[2],stat_log->cpu[2],
																	stat_log->dest,stat_log->violation,stat_log->enb_ue_s1ap_id);
				stat_log=stat_log->next;
				free(tmp);
			}
			
			free(stat_log);
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
		
		/*Fetch message type from the next location */
		uint16_t 	msg_type = get_msg_type(&s1ap_packet);
		uint16_t	slice_id = pkt_identifier->slice_id;
		uint64_t	key = time(NULL);
		//uint64_t	altkey = ~key;
		int			host1;
		slice_id = 1 + slice_id %2;

		// It means that this is the initial request // attach request
		switch(msg_type)
		{
		case ATTACH_REQUEST: 
		
			//In this case we need to select a random host.
			//key = *(uint64_t *)(pkt_data + 4 + sizeof(int));
			key = enb_ue_s1ap_id;
			sprintf(cur_stat_log->msg_type,"ATTACH");
			cur_stat_log->enb_ue_s1ap_id = enb_ue_s1ap_id;
			slice_aware_get_host(0,key);
			host1 = get_viable_host(slice_id,msg_type);
			
			pkt_identifier->MMEID = host1;
			add_connection(slice_id,enb_ue_s1ap_id,host1);
#ifdef LOGS	
			printf("Initial attach request::::key: %lu\n",key);
			printf("destination: %d,slice id: %d,enb_ue_s1ap_id %lu\n",host1,slice_id,enb_ue_s1ap_id);
#endif
			cur_stat_log->next=(proc_stat_t *)malloc(sizeof(proc_stat_t));
			cur_stat_log=cur_stat_log->next;
			break;
		case SERVICE_REQUEST:
			sprintf(cur_stat_log->msg_type,"SERVICE");
			cur_stat_log->enb_ue_s1ap_id = enb_ue_s1ap_id;
			//In this case we need to select a random host.
			//key = *(uint64_t *)(pkt_data + 4 + sizeof(int));
			key = enb_ue_s1ap_id;
			
			slice_aware_get_host(slice_id,key);
			host1 = get_viable_host(slice_id,msg_type);
			//meta->destination = host1;
#ifdef LOGS			
			printf("Initial service request::::key: %lu\n",key);
			printf("destination: %d,slice id: %d,enb_ue_s1ap_id %lu\n",host1,slice_id,enb_ue_s1ap_id);
#endif
			pkt_identifier->MMEID = host1;
			add_connection(slice_id,enb_ue_s1ap_id,host1);
			cur_stat_log->next=(proc_stat_t *)malloc(sizeof(proc_stat_t));
			cur_stat_log=cur_stat_log->next;
			break;
		case DETACH_REQUEST:
			sprintf(cur_stat_log->msg_type,"DETACH");
			cur_stat_log->enb_ue_s1ap_id = enb_ue_s1ap_id;
			//In this case we need to select a random host.
			key = *(uint64_t *)(pkt_data + 4 + sizeof(int));
			slice_aware_get_host(slice_id,key);
			host1 = get_viable_host(slice_id,msg_type);
			//meta->destination = host1;
#ifdef LOGS			
			printf("Initial detach request::::key: %lu\n",key);
			printf("destination: %d,slice id: %d,enb_ue_s1ap_id %lu\n",host1,slice_id,enb_ue_s1ap_id);
#endif
			pkt_identifier->MMEID = host1;
			add_connection(slice_id,enb_ue_s1ap_id,host1);
			cur_stat_log->next=(proc_stat_t *)malloc(sizeof(proc_stat_t));
			cur_stat_log=cur_stat_log->next;
			break;
		default:
#ifdef LOGS			
			printf(":::::::Message type: %d::::::::\n",msg_type);
			//printf("slice id: %d,enb_ue_s1ap_id %lu\n",slice_id,enb_ue_s1ap_id);
			
#endif
			host1 = get_connection(slice_id,enb_ue_s1ap_id);
			if(host1>0)
			{
				//meta->destination = conn[slice_id].host_id;
				pkt_identifier->MMEID = host1;
#ifdef LOGS		
				printf("Connection found\n");
				printf("destination: %d,slice id: %d,enb_ue_s1ap_id %lu\n",host1,slice_id,enb_ue_s1ap_id);
#endif
			}
			else {
				key = *(uint64_t *)(pkt_data + 4 + sizeof(int));
		
				slice_aware_get_host(slice_id,key);
				host1 = get_viable_host(slice_id,msg_type);
				// Now need to check which replica will have a better latency

#ifdef LOGS
				printf("Connection not found\n");
				//printf("slice id: %d,key: %lu\n",slice_id,key);
#endif
				pkt_identifier->MMEID = host1;
				add_connection(slice_id,enb_ue_s1ap_id,meta->destination);
#ifdef LOGS
				printf("destination: %d,slice id: %d,enb_ue_s1ap_id %lu\n",host1,slice_id,enb_ue_s1ap_id);
	
#endif
			}
		}
	
	}
// The below code should be used if you are testing with netperf/iperf
        if (pkt->port == 0) {
                meta->destination = 1;
        }
        else {
                meta->destination = 0;
        }

        return 0;
}
/* we iterate throught the service id in the doc recevied and return the lowest queue size */
static int getstat(cJSON *data, int svcid,stat_t *stat) {
	 char buff[10] = {0};
	 snprintf(buff,10,"%d",svcid);
	 cJSON * svcobj = cJSON_GetObjectItem(data, buff);
	 int min_queue = -1;
	 int lcore_num;
	 //printf("service id: %d\n",svcid);
	 if(svcobj) {
		 cJSON * instobj = svcobj->child;
		 while(instobj) {
			 //printf("queue %d\n",instobj->valueint);
			 //printf("queue %f\n",instobj->valuedouble);
			 //printf("instance %d\n",atoi(instobj->string));
			 cJSON * queue = cJSON_GetObjectItem(instobj,"queue-status");
			 //printf("queue %d\n",queue->valueint);
			 cJSON * lcore = cJSON_GetObjectItem(instobj,"lcore");
			 //printf("lcore %d\n",lcore->valueint);
			 lcore_num = lcore->valueint;
			 if((min_queue == -1)|| (min_queue > queue->valueint)) {
				 min_queue = queue->valueint;
			 }
			//printf("min queue %d\n",min_queue);
			instobj = instobj->next;
		 }
		 cJSON * lcore_set = cJSON_GetObjectItem(data, "lcore");
		 snprintf(buff,10,"%d",lcore_num);
		 cJSON * lcore_usage = cJSON_GetObjectItem(lcore_set, buff);
		 //printf("lcore usage %f\n",lcore_usage->valuedouble);
		 stat->queue_status = min_queue;
		 stat->cpu = 100 - lcore_usage->valuedouble;

	 }
	 //cJSON_SetNumberValue(lcore_cpu_stat, percent_usage);


	if(min_queue <= 0) {
		return 0;
	}

	return min_queue;
}
static int update_thread( __attribute__((unused))  void *args) {
	int key = 1;//only 1 host is available for now
	//char *data;
	//int next;
	//int ret;
	stat_t *arr;
	struct sockaddr_in sock_var;
	int clientFileDiscriptor;
	int serverFileDiscriptor;
	serverFileDiscriptor=socket(AF_INET,SOCK_STREAM,0);
	sock_var.sin_addr.s_addr=inet_addr("0.0.0.0");
	sock_var.sin_port=6000;
	sock_var.sin_family=AF_INET;
	bind(serverFileDiscriptor,(struct sockaddr*)&sock_var,sizeof(sock_var));
	listen(serverFileDiscriptor,0);
	//int buff[MAX_HOSTS] = {0};
	char datalen_buff[20] = {0};
	int retrydelay = 1;


	while(1 ) {
		clientFileDiscriptor = accept(serverFileDiscriptor,NULL,NULL);
		if(clientFileDiscriptor < 0){
			sleep(retrydelay);
			retrydelay *=2;
			if(retrydelay > 60)
				retrydelay = 60;
			continue;
		}
		retrydelay = 1;
		printf("Established socket connection\n");
		while(1) {

			/*first read the size of data */

			if(read(clientFileDiscriptor, datalen_buff, 20) <= 0) {
				printf("connection terminated\n");
				break;

			}
			int datalen = atoi(datalen_buff);
			char * data_buff = malloc(sizeof(char) * (datalen + 1));

			if(read(clientFileDiscriptor, data_buff, sizeof(char)* (datalen + 1)) <= 0) {
				printf("connection terminated\n");
				break;

			}
			//printf("datalen:%d data_buff:%s\n", datalen, data_buff);
			/*
			 * Now that we have received the data, need to use the parser
			 */
			cJSON *data = cJSON_Parse(data_buff);
			//char *temp = cJSON_Print(data);
			//printf("json:\n%s\n", temp);
			//Currently key is hardcoded as 1 as we have only 1 host
			//pthread_mutex_lock(&lock);
			for(key = 0;key<MAX_HOSTS;key++)
			{
				if(all_hosts[key]==1)
				{
					
					if((arr = kvs_get(q_htable, key)) == NULL){
						printf("something is wrong\n");
					}else {
						getstat(data, key,arr);
						
						// This is where you update the table entry
		
						//for(int i = 0 ;i < MAX_SLICEID; i++ ){
							//arr[0] = getstat(data, key);
						//}
		
					}
					
				}
			}
			//pthread_mutex_unlock(&lock);
			//This sleep can be removed.
			//usleep(100);
		}
		close(clientFileDiscriptor);
		clientFileDiscriptor = -1;
	}
	close(serverFileDiscriptor);
	return 0;
}



void init_ring(void)
{
	memset(ring,0,sizeof(int)*3*MAX_HOSTS);
	memset(all_hosts,0,sizeof(int) * MAX_HOSTS);
	FILE *fp;
	fp = fopen("ring_config.dat","r");
	int t=0;
	int slice_id = 0;
	int i=0,j=0;
	char ch[2];
	char c;
	while (1)
	{
		c=fgetc(fp);
		if(c=='~')
		{
			if(t==1)
			{
				ring[slice_id][i] = atoi(ch);
				printf("host = %d\n",ring[slice_id][i]);
				if(all_hosts[atoi(ch)]!=1)
					all_hosts[atoi(ch)] = 1;
				i++;
				j=0;
			}
			else
				t=1;
			continue;
		}
		else if(c=='\n')
		{
			ring[slice_id][i] = atoi(ch);
			printf("host = %d\n",ring[slice_id][i]);
			if(all_hosts[atoi(ch)]!=1)
				all_hosts[atoi(ch)] = 1;
			i++;
			printf("end of slice %d\n",slice_id);
			t=0;
			ring[slice_id][i] = 0;
			i=0;
			j=0;
		}
		else if(t==0)
		{
			ch[0]=c;
			ch[1]='\0';
			slice_id = atoi(ch);
			printf("slice_id = %d\n",slice_id);
			//t = 1;
		}
		else if(t==1)
		{
			ch[j]=c;
			j++;
			ch[j]='\0';
		}
		if(feof(fp))
		{
			ring[slice_id][i] = atoi(ch);
			printf("host = %d\n",ring[slice_id][i]);
			if(all_hosts[atoi(ch)]!=1)
				all_hosts[atoi(ch)] = 1;
			i++;
			printf("EOF encountered\n");
			break;
		}
		
	}
}



int main(int argc, char *argv[]) {
        int arg_offset,i;
        unsigned cur_lcore;
		stat_log = (proc_stat_t *)malloc(sizeof(proc_stat_t));
		cur_stat_log = stat_log;
		//for(int j = 0;j<100;j++)
			//conn[j].conn_count = 0;
		
        //int arr[100] = {0};
		stat_t *host_stats = (stat_t *)malloc(sizeof(stat_t));

        const char *progname = argv[0];

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }
        cur_lcore = rte_lcore_id();
        //key : host value :array of queue status
        kvs_hash_init(q_htable);
        for(i = 1; i <= MAX_HOSTS; i++) {

        	//kvs_set(q_htable, i, s_mem((char *)host_stats, MAX_SLICEID * sizeof(int)));
			kvs_set(q_htable, i, s_mem((char *)host_stats, sizeof(stat_t)));

        }
        cur_lcore = rte_get_next_lcore(cur_lcore, 1, 1);

        rte_eal_remote_launch(update_thread, NULL,  cur_lcore);
		init_ring();
		kvs_hash_init(conn_htable);
		kvs_hash_init(chash_ring);
        add_n_hosts_slice(0);
        add_n_hosts_slice(1);	
        add_n_hosts_slice(2);
        onvm_nflib_run(nf_info, &packet_handler);

		
        printf("If we reach here, program is ending\n");
        return 0;
}
