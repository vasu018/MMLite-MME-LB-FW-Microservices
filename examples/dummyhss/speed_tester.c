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

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <rte_udp.h>


#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "hss.h"



/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;


/* number of package between each print */
static uint32_t print_delay = 10000000;
static uint16_t destination;
static uint8_t use_direct_rings = 0;
static uint8_t keep_running = 1;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay> -a <use_advanced_rings>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, dst_flag = 0;

        while ((c = getopt (argc, argv, "d:p:a:k:")) != -1) {
                switch (c) {
                case 'a':
                        use_direct_rings = 1;
                        break;
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
                RTE_LOG(INFO, APP, "Speed tester NF requires a destination NF with the -d flag.\n");
                return -1;
        }

        return optind;
}

static inline uint16_t
ip_sum(const unaligned_uint16_t *hdr, int hdr_len)
{
        uint32_t sum = 0;

        while (hdr_len > 1)
        {
                sum += *hdr++;
                if (sum & 0x80000000)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                hdr_len -= 2;
        }

        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        return ~sum;
}



int frame_packet_for_hss(struct rte_mbuf *packet, 
                         uint8_t * payload, uint32_t enb_ue_s1ap_id, 
                         pkt_identifier_t *pkt_identifier)
{

#if SERVER_30
    struct ether_addr cfg_ether_dst     =
        {{ 0xa0, 0x36, 0x9f, 0x10, 0xc6, 0x24 }}; // a0:36:9f:10:c6:24 .70
    struct ether_addr cfg_ether_src     =
        {{ 0x90, 0xe2, 0xba, 0x86, 0x7f, 0x91 }}; // 90:e2:ba:86:7f:90 .30
#else
    struct ether_addr cfg_ether_src     =
        {{ 0xa0, 0x36, 0x9f, 0x10, 0xc6, 0x24 }}; // a0:36:9f:10:c6:24 .70
    struct ether_addr cfg_ether_dst     =
        {{ 0x90, 0xe2, 0xba, 0x86, 0x7f, 0x91 }}; // 90:e2:ba:86:7f:90 .30
#endif
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    ip_options_type * ip_opt;
    struct udp_hdr *udp_h;
    char * udp_data;
#ifdef LOGS
        int i = 0;
#endif

    eth_hdr = (struct ether_hdr *)rte_pktmbuf_append(packet, sizeof(struct ether_hdr));
    ether_addr_copy(&cfg_ether_dst,&(eth_hdr->d_addr));
    ether_addr_copy(&cfg_ether_src,&(eth_hdr->s_addr));
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    ipv4_hdr = (struct ipv4_hdr *)rte_pktmbuf_append(packet, sizeof(struct ipv4_hdr));
#if SERVER_30
    ipv4_hdr->dst_addr=rte_cpu_to_be_32(IPv4(30,30,30,35));
    ipv4_hdr->src_addr=rte_cpu_to_be_32(IPv4(30,30,30,30));
#else
    ipv4_hdr->src_addr=rte_cpu_to_be_32(IPv4(30,30,30,35));
    ipv4_hdr->dst_addr=rte_cpu_to_be_32(IPv4(30,30,30,30));
#endif
    ipv4_hdr->version_ihl =IP_VHL_DEF_HSS;
        ipv4_hdr->type_of_service       = 0;
    ipv4_hdr->fragment_offset   = 0;
    ipv4_hdr->time_to_live      = IP_DEFTTL;
    ipv4_hdr->next_proto_id     = IPPROTO_UDP;
    ipv4_hdr->packet_id = 30;
    ipv4_hdr->total_length      = rte_cpu_to_be_16((TXONLY_DEF_PACKET_LEN - 4) - sizeof( struct ether_hdr));
    ipv4_hdr->hdr_checksum = ip_sum((unaligned_uint16_t *)ipv4_hdr,
                                                 sizeof(*ipv4_hdr));

    if(enb_ue_s1ap_id != 0) {
    	ip_opt = (ip_options_type *)rte_pktmbuf_append(packet, sizeof(ip_options_type));
    } else {
	RTE_LOG(INFO, APP, "\n enb_ue_s1ap_id not received\n");
        return -1;
    }

    memcpy(&ip_opt->ip_options[0], &enb_ue_s1ap_id, sizeof(uint32_t));
        /* Initialize UDP header. */
    udp_h = (struct udp_hdr *)rte_pktmbuf_append(packet, sizeof(struct udp_hdr));

    udp_h->src_port     = rte_cpu_to_be_16(htons(2345));
    udp_h->dst_port     = rte_cpu_to_be_16(htons(2345));
    udp_h->dgram_cksum  = 0; /* No UDP checksum. */
    udp_h->dgram_len    = rte_cpu_to_be_16(TXONLY_DEF_PACKET_LEN  -2 -
                                                   sizeof(pkt_identifier_t) -
                                                   sizeof(struct ether_hdr) -
                                                   sizeof(struct ipv4_hdr));

    udp_data= (char *)rte_pktmbuf_append(packet, TXONLY_DEF_PACKET_LEN -2 -
                           sizeof(pkt_identifier_t) -
                           sizeof(struct ether_hdr) -
                           sizeof(struct ipv4_hdr));


    memcpy(udp_data, pkt_identifier, sizeof(pkt_identifier_t));

#if 1
        memcpy(udp_data + sizeof(pkt_identifier_t), payload,
                            (TXONLY_DEF_PACKET_LEN - 2) -
                           sizeof(struct ether_hdr) -
                           sizeof(struct ipv4_hdr));
#endif
#ifdef LOGS
        for(i = 0; i < 15; i++)
                printf("0x%x ", payload[i]);
#endif
#if 0
    strncpy(udp_data,"Fire on the mountain\r\n",(TXONLY_DEF_PACKET_LEN - 4) -
                           sizeof(struct ether_hdr) -
                           sizeof(struct ipv4_hdr));
#endif

    packet->nb_segs             = 1;
    packet->pkt_len             = packet->data_len;
    packet->ol_flags            = 386;
    packet->vlan_tci            = 0;
    packet->vlan_tci_outer      = 0;
    packet->l2_len              = sizeof(struct ether_hdr);
    packet->l3_len              = sizeof(struct ipv4_hdr);
    packet->l4_len				= sizeof(struct udp_hdr);

    return 0;
}




#if 0

static void 
spoof_packets(int packet_type, int num_packets, uint32_t *enb_ue_s1ap_id_p)
{
    struct rte_mempool *pktmbuf_pool;
    struct rte_mbuf* pkts[num_packets];
    int i;

    pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    if(pktmbuf_pool == NULL) {
        onvm_nflib_stop();
        rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
    }
    printf("Creating %d packets to send to %d\n", num_packets, destination);

    auth_params_t auth_params = {{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
        {2,2,2,2,2,2},{3,3,3,3,3,3}};

    for (i=0; i < num_packets; i++) {
        struct onvm_pkt_meta* pmeta;
        pkts[i] = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(pkts[i]);
        pmeta->destination = destination;
        pmeta->action = ONVM_NF_ACTION_TONF;
        //pkts[i]->hash.rss = i;
        if(packet_type == CREATE_PACKET_AUTH) {
            pmeta->flags = ONVM_SET_BIT(0, SPEED_TESTER_BIT);
            memcpy(((char*)pkts[i]->buf_addr + pkts[i]->data_off + sizeof(uint32_t)),
                   &auth_params, sizeof(auth_params_t));
        } else if(packet_type == CREATE_PACKET_LOCATION_UPDATE) {
            pmeta->flags = ONVM_SET_BIT(0, LOCATION_UPDATE_BIT);
            memcpy(((char*)pkts[i]->buf_addr + pkts[i]->data_off + sizeof(uint32_t)),
                   &auth_params, sizeof(auth_params_t));
        }
	memcpy(((char*)pkts[i]->buf_addr + pkts[i]->data_off),
                   enb_ue_s1ap_id_p, sizeof(uint32_t));
	printf("\nspoof_packets: enb_ue_s1ap_id_p = 0x%x\n",*(uint32_t*)((char*)pkts[i]->buf_addr + pkts[i]->data_off));

        onvm_nflib_return_pkt(pkts[i]);
    }
}

#endif

ip_options_type*
hss_pkt_ipopt_hdr(struct rte_mbuf* pkt) {
        struct ipv4_hdr* ipv4 = onvm_pkt_ipv4_hdr(pkt);

        if (unlikely(ipv4 == NULL)) {  // Since we aren't dealing with IPv6 packets for now, we can ignore anything that isn't IPv4
                return NULL;
        }

        if ((ipv4->version_ihl&0x0f) <= 5) {
                return NULL;
        }

        uint8_t* pkt_data = rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
        return (ip_options_type*)pkt_data;
}



/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf* pkt) {
        static uint64_t last_cycles;
        static uint64_t cur_pkts = 0;
        static uint64_t last_pkts = 0;
        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
        (void)pkt;

        uint64_t cur_cycles = rte_get_tsc_cycles();
        cur_pkts += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("Total packets: %9"PRIu64" \n", cur_pkts);
        printf("TX pkts per second: %9"PRIu64" \n", (cur_pkts - last_pkts)
                * rte_get_timer_hz() / (cur_cycles - last_cycles));
        printf("Packets per group: %d\n", NUM_PKTS);

        last_pkts = cur_pkts;
        last_cycles = cur_cycles;

        printf("\n\n");
}

static int
s6a_generate_authentication_info_req_hss(struct rte_mbuf* pkt, pkt_identifier_t *pkt_identifier)
{

        struct rte_mbuf* auth_req;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = {0x01, 0x00, 0x01, 0x30, 0x40, 0x00, 0x01, 0x3e, 0x01, 0x00, 0x00, 0x23, 0x23, 0x2e, 0xcf, 0xd5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x40, 0x00, 0x00, 0x38, 0x76, 0x61, 0x73, 0x75, 0x64, 0x65, 0x76, 0x61, 0x6e, 0x65, 0x70, 0x63, 0x32, 0x2e, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x3b, 0x31, 0x34, 0x39, 0x30, 0x36, 0x37, 0x37, 0x37, 0x37, 0x35, 0x3b, 0x31, 0x3b, 0x61, 0x70, 0x70, 0x73, 0x36, 0x61, 0x00, 0x00, 0x05, 0x85, 0xc0, 0x00, 0x00, 0x90, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x05, 0x86, 0xc0, 0x00, 0x00, 0x84, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x05, 0xa7, 0xc0, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x28, 0xaf, 0xf2, 0x1c, 0x6e, 0x32, 0xa6, 0x4a, 0x09, 0x49, 0xed, 0x8e, 0x9d, 0x06, 0xb8, 0xf0, 0x93, 0x62, 0x00, 0x00, 0x05, 0xa8, 0xc0, 0x00, 0x00, 0x14, 0x00, 0x00, 0x28, 0xaf, 0xdc, 0x07, 0x4b, 0xb2, 0xd6, 0x44, 0x54, 0x8d, 0x00, 0x00, 0x05, 0xa9, 0xc0, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x28, 0xaf, 0xd7, 0x12, 0x86, 0x9d, 0x52, 0xb8, 0x80, 0x00, 0x60, 0x15, 0x2f, 0xf7, 0x7c, 0x74, 0xa2, 0x36, 0x00, 0x00, 0x05, 0xaa, 0xc0, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x28, 0xaf, 0x6f, 0xdd, 0xea, 0x4f, 0x8a, 0xda, 0x0b, 0xba, 0x66, 0xec, 0xa4, 0x34, 0xef, 0xa5, 0xdc, 0x69, 0xac, 0xb6, 0x27, 0x1a, 0x46, 0x3e, 0x27, 0xce, 0x7b, 0x92, 0xdb, 0xa6, 0x8c, 0xd1, 0xed, 0x7a, 0x00, 0x00, 0x01, 0x15, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x24, 0x76, 0x61, 0x73, 0x75, 0x64, 0x65, 0x76, 0x61, 0x6e, 0x65, 0x70, 0x63, 0x32, 0x2e, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x28, 0x40, 0x00, 0x00, 0x16, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x07, 0xd1};
        //struct ipv4_hdr* ipv4 = (struct ipv4_hdr*)(&packet[0] + sizeof(struct ether_hdr));
//        int i;
//        ue_context_t * ue_context;
        uint32_t enb_ue_s1ap_id = 0;
        ip_options_type* ip_opt;
//      memcpy(&enb_ue_s1ap_id, rte_pktmbuf_mtod(pkt, uint8_t*), sizeof(uint32_t));
//      printf("\nenb_ue_s1ap_id = 0x%x \n", enb_ue_s1ap_id);
        //TODO get enb_ue_s1ap_id from ue_contex
        ip_opt= hss_pkt_ipopt_hdr(pkt);
        if(ip_opt == NULL)
                RTE_LOG(INFO, APP, "ERROR: enb_ue_s1ap_id not present");
        else
                memcpy(&enb_ue_s1ap_id, &ip_opt->ip_options[0], sizeof(uint32_t));



        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

#if 0
        printf("enb_id=%d\n",ip_opt->ip_options[0]);
        printf("enb_id=%d\n",enb_ue_s1ap_id);
#endif


        auth_req = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(auth_req);
        pmeta->destination = MME_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;

        //ipv4->src_addr = IPv4(130,245,144,70);
        //ipv4->dst_addr = IPv4(130,245,144,30);

        if (frame_packet_for_hss(auth_req, &packet[0], enb_ue_s1ap_id, pkt_identifier) != 0) {
            RTE_LOG(INFO, APP, "*************** Packet framed badly.. returning ****************\n");
            return -1;
        }
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "*************** Authentication parameters sent from HSS ****************\n");
#endif
//        RTE_LOG(INFO, APP, "ip = %o.%o.%o.%o \n", packet[26],packet[27],packet[28],packet[29] );
        onvm_nflib_return_pkt(auth_req);

#if 0
    struct rte_mbuf* auth_req = pkt;
    char auth_req_query[MAX_BUF_LEN], *data; 
    uint32_t *enb_ue_s1ap_id_p;

    data = (char*)((char*)auth_req->buf_addr + auth_req->data_off + sizeof(uint8_t) + sizeof(uint32_t));
    enb_ue_s1ap_id_p = (uint32_t *)((char*)auth_req->buf_addr + auth_req->data_off + sizeof(uint8_t));

    memcpy(auth_req_query, data, strlen(data));

    
    printf("\n%s\n",auth_req_query);
    printf("\n0x%x\n",*enb_ue_s1ap_id_p);
    /*
     * Check the MySQL query and send back the reqested msg
     * TODO: Check properly
     */
    spoof_packets(CREATE_PACKET_AUTH, 1, enb_ue_s1ap_id_p);
#endif
    return 0;

}

static int
s6a_update_location_req_hss(struct rte_mbuf* pkt, pkt_identifier_t *pkt_identifier)
{
        struct rte_mbuf* auth_req;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = {0x01, 0x00, 0x02, 0x2c, 0x40, 0x00, 0x01, 0x3c, 0x01, 0x00, 0x00, 0x23, 0x23, 0x2e, 0xcf, 0xd6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x40, 0x00, 0x00, 0x38, 0x76, 0x61, 0x73, 0x75, 0x64, 0x65, 0x76, 0x61, 0x6e, 0x65, 0x70, 0x63, 0x32, 0x2e, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x3b, 0x31, 0x34, 0x39, 0x30, 0x36, 0x37, 0x37, 0x37, 0x37, 0x35, 0x3b, 0x32, 0x3b, 0x61, 0x70, 0x70, 0x73, 0x36, 0x61, 0x00, 0x00, 0x05, 0x7e, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x05, 0x78, 0xc0, 0x00, 0x01, 0x7c, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x02, 0xbd, 0xc0, 0x00, 0x00, 0x12, 0x00, 0x00, 0x28, 0xaf, 0x33, 0x63, 0x80, 0x30, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x05, 0x92, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x05, 0x90, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x89, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x05, 0x9b, 0xc0, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x02, 0x04, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x02, 0xfa, 0xf0, 0x80, 0x00, 0x00, 0x02, 0x03, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x05, 0xf5, 0xe1, 0x00, 0x00, 0x00, 0x05, 0x95, 0xc0, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x05, 0x8f, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x94, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x96, 0xc0, 0x00, 0x00, 0xc4, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x05, 0x8f, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xb0, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xed, 0xc0, 0x00, 0x00, 0x14, 0x00, 0x00, 0x28, 0xaf, 0x6f, 0x61, 0x69, 0x2e, 0x69, 0x70, 0x76, 0x34, 0x00, 0x00, 0x05, 0x97, 0xc0, 0x00, 0x00, 0x58, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x04, 0x04, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x04, 0x0a, 0x80, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x04, 0x16, 0x80, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x04, 0x17, 0x80, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x18, 0x80, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x9b, 0xc0, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x02, 0x04, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x02, 0xfa, 0xf0, 0x80, 0x00, 0x00, 0x02, 0x03, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x05, 0xf5, 0xe1, 0x00, 0x00, 0x00, 0x06, 0x53, 0x80, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x01, 0x15, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x24, 0x76, 0x61, 0x73, 0x75, 0x64, 0x65, 0x76, 0x61, 0x6e, 0x65, 0x70, 0x63, 0x32, 0x2e, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x28, 0x40, 0x00, 0x00, 0x16, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x07, 0xd1};
        //struct ipv4_hdr* ipv4 = (struct ipv4_hdr*)(&packet[0] + sizeof(struct ether_hdr));
//        int i;
//        ue_context_t * ue_context;
        uint32_t enb_ue_s1ap_id = 0;
        ip_options_type* ip_opt;
//      memcpy(&enb_ue_s1ap_id, rte_pktmbuf_mtod(pkt, uint8_t*), sizeof(uint32_t));
//      printf("\nenb_ue_s1ap_id = 0x%x \n", enb_ue_s1ap_id);
        //TODO get enb_ue_s1ap_id from ue_contex
        ip_opt= hss_pkt_ipopt_hdr(pkt);
        if(ip_opt == NULL)
                RTE_LOG(INFO, APP, "ERROR: enb_ue_s1ap_id not present");
        else
                memcpy(&enb_ue_s1ap_id, &ip_opt->ip_options[0], sizeof(uint32_t));



        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }
        auth_req = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(auth_req);
        pmeta->destination = MME_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;

        //ipv4->src_addr = IPv4(130,245,144,70);
        //ipv4->dst_addr = IPv4(130,245,144,30);

        if (frame_packet_for_hss(auth_req, &packet[0], enb_ue_s1ap_id, pkt_identifier) != 0) {
            RTE_LOG(INFO, APP, "*************** Packet framed badly.. returning ****************\n");
            return -1;
        }
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "*************** LOCATION UPDATE sent from HSS ****************\n");
#endif
//        RTE_LOG(INFO, APP, "ip = %o.%o.%o.%o \n", packet[26],packet[27],packet[28],packet[29] );
        onvm_nflib_return_pkt(auth_req);




#if 0
    struct rte_mbuf* auth_req = pkt;
    char loc_up_query[MAX_BUF_LEN], *data;
    uint32_t *enb_ue_s1ap_id_p;

    enb_ue_s1ap_id_p = (uint32_t *)((char*)auth_req->buf_addr + auth_req->data_off + sizeof(uint8_t));
    data = (char*)((char*)auth_req->buf_addr + auth_req->data_off + sizeof(uint8_t) + sizeof(uint32_t));

    memcpy(loc_up_query, data, strlen(data)); 
    printf("\n%s\n",loc_up_query);

    /*
     * Check the MySQL query and send back the reqested msg
     * TODO: Check properly
     */
    spoof_packets(CREATE_PACKET_LOCATION_UPDATE, 1, enb_ue_s1ap_id_p);
#endif

    return 0;
}

#if 0
static int
s6a_packet_handler(struct rte_mbuf* pkt)
{
    struct rte_mbuf* auth_req = pkt;
    char *data;
    uint8_t identifier;

    
    data = (char*)((char*)auth_req->buf_addr + auth_req->data_off);

    identifier = (uint8_t)*data;
    
    if (identifier == MME_LOC_UPDATE_GET_MMEID) {
        printf("\n\nReceived Location Update Request\n");
        s6a_update_location_req_hss(pkt);
    } else if (identifier == MME_AUTH_REQ){
        printf("\n\nReceived authentication\n");
        s6a_generate_authentication_info_req_hss(pkt);
    } else {
        printf("\nUnknown packet received ID:%d\n",identifier);
    }

    return 0;

}
#endif


static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
        static uint32_t counter = 0;
	uint8_t* s6a_pkt_data;
	uint32_t s6_command_code = 0;
	uint8_t ip_options_length = 0;
	struct ipv4_hdr *ip;
	uint8_t i;
	pkt_identifier_t *pkt_identifier;

        if (counter++ == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }
        meta->action = ONVM_NF_ACTION_DROP;

	ip = onvm_pkt_ipv4_hdr(pkt);

        if (ip != NULL) {
                if(ip->next_proto_id == 132) {
#ifdef LOGS
                        RTE_LOG(INFO, APP, "sctp packet\n");
#endif
                } else if(ip->next_proto_id == 17) {
#ifdef LOGS
                        RTE_LOG(INFO, APP, "udp packet\n");
#endif
                } else {
                        return 0;
                }

        } else {
                printf("No IP4 header found\n");
                return 0;
        }
        if((ip->version_ihl&0x0f) > 5)
                ip_options_length = ((ip->version_ihl&0x0f) - 5) * 32;

	s6a_pkt_data = rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(pkt_identifier_t) + sizeof(struct udphdr);
	pkt_identifier = (pkt_identifier_t*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(struct udphdr));
        //        onvm_pkt_print(pkt);
        //        print_hex((uint8_t *)s1ap_pkt_data, 96);

#ifdef LOGS
        printf("%s:%d PKT_ID : msg_type:%d  slice_id:%d\n",
               __func__, __LINE__,
               pkt_identifier->msg_type,
               pkt_identifier->slice_id);
#endif
        if(s6a_pkt_data == NULL) {
            RTE_LOG(ERR, APP, "No s6a header found");
            return 0;
        }

        for(i = 0; i < 3; i++)
                s6_command_code = s6_command_code*256 + *(uint8_t*)(s6a_pkt_data + 5 + i);

        switch(s6_command_code){

        case S6A_AUTH_INFO:
#ifdef LOGS
                RTE_LOG(INFO, APP, "\n\n\n");
                RTE_LOG(INFO, APP, "*************** UE Authentication parameters received from MME ****************\n");
#endif
                s6a_generate_authentication_info_req_hss(pkt, pkt_identifier);
                break;

        case S6A_LAU:
#ifdef LOGS
                RTE_LOG(INFO, APP, "\n\n\n");
                RTE_LOG(INFO, APP, "*************** LOCATION UPDATE response received from HSS ****************\n");
#endif
                s6a_update_location_req_hss(pkt, pkt_identifier);
                break;
        
        default:
                RTE_LOG(INFO, APP, "\n\n\n");
                RTE_LOG(INFO, APP, "No Valid command code found!! : %d\n",s6_command_code);
                break;
        }
        return 0;
}

static void
handle_signal(int sig)
{
        if (sig == SIGINT || sig == SIGTERM)
                keep_running = 0;
}


static void
run_advanced_rings(void) {
        void *pkts[PKT_READ_SIZE];
        struct onvm_pkt_meta* meta;
        uint16_t i, j, nb_pkts;
        void *pktsTX[PKT_READ_SIZE];
        int tx_batch_size;
        struct rte_ring *rx_ring;
        struct rte_ring *tx_ring;
        volatile struct client_tx_stats *tx_stats;

        printf("Process %d handling packets using advanced rings\n", nf_info->instance_id);
        printf("[Press Ctrl-C to quit ...]\n");

        /* Listen for ^C and docker stop so we can exit gracefully */
        signal(SIGINT, handle_signal);
        signal(SIGTERM, handle_signal);

        /* Get rings from nflib */
        rx_ring = onvm_nflib_get_rx_ring(nf_info);
        tx_ring = onvm_nflib_get_tx_ring(nf_info);
        tx_stats = onvm_nflib_get_tx_stats(nf_info);

        while (keep_running && rx_ring && tx_ring && tx_stats) {
                tx_batch_size= 0;
                /* Dequeue all packets in ring up to max possible. */
		nb_pkts = rte_ring_dequeue_burst(rx_ring, pkts, PKT_READ_SIZE);

                if(unlikely(nb_pkts == 0)) {
                        continue;
                }
                /* Process all the packets */
                for (i = 0; i < nb_pkts; i++) {
                        meta = onvm_get_pkt_meta((struct rte_mbuf*)pkts[i]);
                        packet_handler((struct rte_mbuf*)pkts[i], meta);
                        pktsTX[tx_batch_size++] = pkts[i];
                }

                if (unlikely(tx_batch_size > 0 && rte_ring_enqueue_bulk(tx_ring, pktsTX, tx_batch_size) == -ENOBUFS)) {
                        tx_stats->tx_drop[nf_info->instance_id] += tx_batch_size;
                        for (j = 0; j < tx_batch_size; j++) {
                                rte_pktmbuf_free(pktsTX[j]);
                        }
                } else {
                        tx_stats->tx[nf_info->instance_id] += tx_batch_size;
                }

        }
        onvm_nflib_stop();
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
        if (use_direct_rings) {
                run_advanced_rings();
        } else {
                onvm_nflib_run(nf_info, &packet_handler);
        }
        printf("If we reach here, program is ending\n");
        return 0;
}
