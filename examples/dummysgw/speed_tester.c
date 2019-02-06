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
#include "sgw.h"

#define NF_TAG "speed"

#define NUM_PKTS 128
#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define PKT_READ_SIZE  ((uint16_t)32)
#define SGW_CREATE_SESSION 5
#define SPEED_TESTER_BIT 7

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


int frame_packet_from_sgw(struct rte_mbuf *packet, uint8_t * payload, 
                           uint32_t enb_ue_s1ap_id, uint8_t msg_type, uint8_t slice_id)
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
    pkt_identifier_t pkt_identifier;

    pkt_identifier.msg_type = msg_type;
    pkt_identifier.slice_id = slice_id;


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

    udp_h->src_port     = rte_cpu_to_be_16(htons(2347));
    udp_h->dst_port     = rte_cpu_to_be_16(htons(2347));
    udp_h->dgram_cksum  = 0; /* No UDP checksum. */
    udp_h->dgram_len    = rte_cpu_to_be_16(TXONLY_DEF_PACKET_LEN  -2 -
                                                   sizeof(pkt_identifier_t) -
                                                   sizeof(struct ether_hdr) -
                                                   sizeof(struct ipv4_hdr));

    udp_data= (char *)rte_pktmbuf_append(packet, TXONLY_DEF_PACKET_LEN -2 -
                           sizeof(pkt_identifier_t) -
                           sizeof(struct ether_hdr) -
                           sizeof(struct ipv4_hdr));


    memcpy(udp_data, &pkt_identifier, sizeof(pkt_identifier_t));

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


ip_options_type*
sgw_pkt_ipopt_hdr(struct rte_mbuf* pkt) {
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

 //   auth_params_t auth_params = {{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
 //       {2,2,2,2,2,2},{3,3,3,3,3,3}};

    uint8_t create_session_rsp[] = {0x48, 0x21, 0x00, 0x71, 0x00, 0x00, 0x02, 0x00, 0x00, 0x55, 0x40, 0x00, 0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x09, 0x00, 0x8b, 0x00, 0x00, 0x00, 0x0b, 0x7f, 0x00, 0x0b, 0x02, 0x57, 0x00, 0x09, 0x01, 0x87, 0x00, 0x00, 0x00, 0x0b, 0x7f, 0x00, 0x0b, 0x02, 0x4f, 0x00, 0x05, 0x00, 0x01, 0x0a, 0x0a, 0x0a, 0x16, 0x7f, 0x00, 0x01, 0x00, 0x00, 0x4e, 0x00, 0x1b, 0x00, 0x80, 0x80, 0x21, 0x10, 0x03, 0x00, 0x00, 0x10, 0x81, 0x06, 0x08, 0x08, 0x08, 0x08, 0x83, 0x06, 0x08, 0x08, 0x04, 0x04, 0x00, 0x0d, 0x04, 0x08, 0x08, 0x08, 0x08, 0x5d, 0x00, 0x18, 0x00, 0x49, 0x00, 0x01, 0x00, 0x05, 0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x09, 0x00, 0x81, 0x00, 0x00, 0x10, 0x00, 0x64, 0x64, 0x0a, 0x39};

    for (i=0; i < num_packets; i++) {
        struct onvm_pkt_meta* pmeta;
        pkts[i] = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(pkts[i]);
        pmeta->destination = destination;
        pmeta->action = ONVM_NF_ACTION_TONF;
        pmeta->flags = ONVM_SET_BIT(0, SGW_CREATE_SESSION);
        //pkts[i]->hash.rss = i;
        if(packet_type == CREATE_SESSION_RESP) {
	    memcpy(((char*)pkts[i]->buf_addr + pkts[i]->data_off),
                   enb_ue_s1ap_id_p, sizeof(uint32_t));
            memcpy(((char*)pkts[i]->buf_addr + pkts[i]->data_off + sizeof(uint32_t)),
                   &create_session_rsp, sizeof(create_session_rsp));
        }
        onvm_nflib_return_pkt(pkts[i]);
    }
}

#endif

static int
s11_send_delete_session_resp(struct rte_mbuf* pkt, pkt_identifier_t *pkt_identifier)
{

        struct rte_mbuf* delete_ses_rsp;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = {0x48, 0x25, 0x00, 0x71, 0x00, 0x00, 0x02, 0x00, 0x00, 0x55, 0x40, 0x00, 0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x09, 0x00, 0x8b, 0x00, 0x00, 0x00, 0x0b, 0x7f, 0x00, 0x0b, 0x02, 0x57, 0x00, 0x09, 0x01, 0x87, 0x00, 0x00, 0x00, 0x0b, 0x7f, 0x00, 0x0b, 0x02, 0x4f, 0x00, 0x05, 0x00, 0x01, 0x0a, 0x0a, 0x0a, 0x16, 0x7f, 0x00, 0x01, 0x00, 0x00, 0x4e, 0x00, 0x1b, 0x00, 0x80, 0x80, 0x21, 0x10, 0x03, 0x00, 0x00, 0x10, 0x81, 0x06, 0x08, 0x08, 0x08, 0x08, 0x83, 0x06, 0x08, 0x08, 0x04, 0x04, 0x00, 0x0d, 0x04, 0x08, 0x08, 0x08, 0x08, 0x5d, 0x00, 0x18, 0x00, 0x49, 0x00, 0x01, 0x00, 0x05, 0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x09, 0x00, 0x81, 0x00, 0x00, 0x10, 0x00, 0x64, 0x64, 0x0a, 0x39};
        uint32_t enb_ue_s1ap_id = 0;
        ip_options_type* ip_opt;
        //TODO get enb_ue_s1ap_id from ue_contex
        ip_opt= sgw_pkt_ipopt_hdr(pkt);
        if(ip_opt == NULL)
                RTE_LOG(INFO, APP, "ERROR: enb_ue_s1ap_id not present");
        else
                memcpy(&enb_ue_s1ap_id, &ip_opt->ip_options[0], sizeof(uint32_t));



        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }


        delete_ses_rsp = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(delete_ses_rsp);
        pmeta->destination = MME_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;

        //ipv4->src_addr = IPv4(130,245,144,70);
        //ipv4->dst_addr = IPv4(130,245,144,30);

        frame_packet_from_sgw(delete_ses_rsp, &packet[0], enb_ue_s1ap_id, pkt_identifier->msg_type, pkt_identifier->slice_id);
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "************** Delete Session Response sent from SGW ****************\n");
#endif
//        RTE_LOG(INFO, APP, "ip = %o.%o.%o.%o \n", packet[26],packet[27],packet[28],packet[29] );
        onvm_nflib_return_pkt(delete_ses_rsp);
        return 0;

}


static int
s11_send_create_session_resp(struct rte_mbuf* pkt, pkt_identifier_t *pkt_identifier)
{

        struct rte_mbuf* create_ses_rsp;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = {0x48, 0x21, 0x00, 0x71, 0x00, 0x00, 0x02, 0x00, 0x00, 0x55, 0x40, 0x00, 0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x09, 0x00, 0x8b, 0x00, 0x00, 0x00, 0x0b, 0x7f, 0x00, 0x0b, 0x02, 0x57, 0x00, 0x09, 0x01, 0x87, 0x00, 0x00, 0x00, 0x0b, 0x7f, 0x00, 0x0b, 0x02, 0x4f, 0x00, 0x05, 0x00, 0x01, 0x0a, 0x0a, 0x0a, 0x16, 0x7f, 0x00, 0x01, 0x00, 0x00, 0x4e, 0x00, 0x1b, 0x00, 0x80, 0x80, 0x21, 0x10, 0x03, 0x00, 0x00, 0x10, 0x81, 0x06, 0x08, 0x08, 0x08, 0x08, 0x83, 0x06, 0x08, 0x08, 0x04, 0x04, 0x00, 0x0d, 0x04, 0x08, 0x08, 0x08, 0x08, 0x5d, 0x00, 0x18, 0x00, 0x49, 0x00, 0x01, 0x00, 0x05, 0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x09, 0x00, 0x81, 0x00, 0x00, 0x10, 0x00, 0x64, 0x64, 0x0a, 0x39};
        //struct ipv4_hdr* ipv4 = (struct ipv4_hdr*)(&packet[0] + sizeof(struct ether_hdr));
//        int i;
//        ue_context_t * ue_context;
        uint32_t enb_ue_s1ap_id = 0;
        ip_options_type* ip_opt;
//      memcpy(&enb_ue_s1ap_id, rte_pktmbuf_mtod(pkt, uint8_t*), sizeof(uint32_t));
//      printf("\nenb_ue_s1ap_id = 0x%x \n", enb_ue_s1ap_id);
        //TODO get enb_ue_s1ap_id from ue_contex
        ip_opt= sgw_pkt_ipopt_hdr(pkt);
        if(ip_opt == NULL)
                RTE_LOG(INFO, APP, "ERROR: enb_ue_s1ap_id not present");
        else
                memcpy(&enb_ue_s1ap_id, &ip_opt->ip_options[0], sizeof(uint32_t));



        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }


        create_ses_rsp = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(create_ses_rsp);
        pmeta->destination = MME_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;

        //ipv4->src_addr = IPv4(130,245,144,70);
        //ipv4->dst_addr = IPv4(130,245,144,30);

        frame_packet_from_sgw(create_ses_rsp, &packet[0], enb_ue_s1ap_id, pkt_identifier->msg_type, pkt_identifier->slice_id);
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "************** Create Session Response sent from SGW ****************\n");
#endif
//        RTE_LOG(INFO, APP, "ip = %o.%o.%o.%o \n", packet[26],packet[27],packet[28],packet[29] );
        onvm_nflib_return_pkt(create_ses_rsp);
 	return 0;

}


static int
s11_send_modify_bearer_resp(struct rte_mbuf* pkt, pkt_identifier_t *pkt_identifier)
{

        struct rte_mbuf* create_ses_rsp;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = {0x48, 0x23, 0x00, 0x71, 0x00, 0x00, 0x02, 0x00, 0x00, 0x55, 0x40, 0x00, 0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x09, 0x00, 0x8b, 0x00, 0x00, 0x00, 0x0b, 0x7f, 0x00, 0x0b, 0x02, 0x57, 0x00, 0x09, 0x01, 0x87, 0x00, 0x00, 0x00, 0x0b, 0x7f, 0x00, 0x0b, 0x02, 0x4f, 0x00, 0x05, 0x00, 0x01, 0x0a, 0x0a, 0x0a, 0x16, 0x7f, 0x00, 0x01, 0x00, 0x00, 0x4e, 0x00, 0x1b, 0x00, 0x80, 0x80, 0x21, 0x10, 0x03, 0x00, 0x00, 0x10, 0x81, 0x06, 0x08, 0x08, 0x08, 0x08, 0x83, 0x06, 0x08, 0x08, 0x04, 0x04, 0x00, 0x0d, 0x04, 0x08, 0x08, 0x08, 0x08, 0x5d, 0x00, 0x18, 0x00, 0x49, 0x00, 0x01, 0x00, 0x05, 0x02, 0x00, 0x02, 0x00, 0x10, 0x00, 0x57, 0x00, 0x09, 0x00, 0x81, 0x00, 0x00, 0x10, 0x00, 0x64, 0x64, 0x0a, 0x39};
        //struct ipv4_hdr* ipv4 = (struct ipv4_hdr*)(&packet[0] + sizeof(struct ether_hdr));
//        int i;
//        ue_context_t * ue_context;
        uint32_t enb_ue_s1ap_id = 0;
        ip_options_type* ip_opt;
//      memcpy(&enb_ue_s1ap_id, rte_pktmbuf_mtod(pkt, uint8_t*), sizeof(uint32_t));
//      printf("\nenb_ue_s1ap_id = 0x%x \n", enb_ue_s1ap_id);
        //TODO get enb_ue_s1ap_id from ue_contex
        ip_opt= sgw_pkt_ipopt_hdr(pkt);
        if(ip_opt == NULL)
                RTE_LOG(INFO, APP, "ERROR: enb_ue_s1ap_id not present");
        else
                memcpy(&enb_ue_s1ap_id, &ip_opt->ip_options[0], sizeof(uint32_t));



        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }


        create_ses_rsp = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(create_ses_rsp);
        pmeta->destination = MME_PORT;

        pmeta->action = ONVM_NF_ACTION_OUT;

        //ipv4->src_addr = IPv4(130,245,144,70);
        //ipv4->dst_addr = IPv4(130,245,144,30);

        frame_packet_from_sgw(create_ses_rsp, &packet[0], enb_ue_s1ap_id, pkt_identifier->msg_type, pkt_identifier->slice_id);
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "************** Create Session Response sent from SGW ****************\n");
#endif
//        RTE_LOG(INFO, APP, "ip = %o.%o.%o.%o \n", packet[26],packet[27],packet[28],packet[29] );
        onvm_nflib_return_pkt(create_ses_rsp);
        return 0;
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
#if 0
static int
s6a_generate_authentication_info_req_hss(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta)
{

    struct rte_mbuf* auth_req = pkt;
//    char* auth_req_query, *data;

    RTE_LOG(INFO, APP, "In %s:%d\n",__func__, __LINE__);
//    auth_req_query = malloc(100);
    
    ///data = (char*)((char*)auth_req->buf_addr + auth_req->data_off);

//    memcpy(auth_req_query, data, strlen(data)); 
  //  printf("\n%s\n",auth_req_query);

    /*
     * Check the MySQL query and send back the reqested msg
     * TODO: Check properly
     */
    spoof_packets(CREATE_SESSION_RESP, 1);

  //  free(auth_req_query);
    printf("\n%p\n",meta);
    return 0;

}
#endif
#if 0
static int
s6a_update_location_req_hss(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta)
{

    struct rte_mbuf* auth_req = pkt;
    char* auth_req_query, *data;

    RTE_LOG(INFO, APP, "In %s:%d\n",__func__, __LINE__);
    auth_req_query = malloc(100);
    
    data = (char*)((char*)auth_req->buf_addr + auth_req->data_off);

    memcpy(auth_req_query, data, strlen(data)); 
    printf("\n%s\n",auth_req_query);

    /*
     * Check the MySQL query and send back the reqested msg
     * TODO: Check properly
     */
    spoof_packets(CREATE_PACKET_AUTH, 1);


    printf("\n%p\n",meta);
    return 0;

}
#endif

static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
        static uint32_t counter = 0;
//	uint32_t *enb_ue_s1ap_id_p;
	uint8_t* s11_pkt_data;
        uint8_t s11_msg_type = 0;
        uint8_t ip_options_length = 0;
        struct ipv4_hdr *ip;
	pkt_identifier_t *pkt_identifier;


        if (counter++ == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }

        meta->action = ONVM_NF_ACTION_DROP;

        ip = onvm_pkt_ipv4_hdr(pkt);
        if((ip->version_ihl&0x0f) > 5)
                ip_options_length = ((ip->version_ihl&0x0f) - 5) * 32;

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
        }

        s11_pkt_data = rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(pkt_identifier_t) + sizeof(struct udphdr);
        pkt_identifier = (pkt_identifier_t*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(struct udphdr));

        //        onvm_pkt_print(pkt);
        //        print_hex((uint8_t *)s1ap_pkt_data, 96);

        if(s11_pkt_data == NULL) {
            RTE_LOG(ERR, APP, "No s11 header found");
            return 0;
        }

	s11_msg_type = * (s11_pkt_data+1);	


        switch(s11_msg_type){

        case S11_CREATE_SESSION_REQ:
#ifdef LOGS
                RTE_LOG(INFO, APP, "\n\n\n");
                RTE_LOG(INFO, APP, "***************Received Create Session Request in SGW  ****************\n");
#endif
                s11_send_create_session_resp(pkt, pkt_identifier);
                break;

        case S11_MODIFY_BEARER_REQ:
#ifdef LOGS
                RTE_LOG(INFO, APP, "\n\n\n");
                RTE_LOG(INFO, APP, "*************** Modify Bearer request received in SGW ****************\n");
#endif
                s11_send_modify_bearer_resp(pkt, pkt_identifier);
                break;

	case S11_DELETE_SESSION_REQ:
#ifdef LOGS
                RTE_LOG(INFO, APP, "\n\n\n");
                RTE_LOG(INFO, APP, "*************** Delete Session request received in SGW ****************\n");
#endif
                s11_send_delete_session_resp(pkt, pkt_identifier);
                break;


        default:
                RTE_LOG(INFO, APP, "\n\n\n");
                RTE_LOG(INFO, APP, "No Valid command code found!! : %d\n",s11_msg_type);
                break;

        }


	

#if 0
        if(ONVM_CHECK_BIT(meta->flags, SPEED_TESTER_BIT)) {
                /* one of our fake pkts to forward */
                meta->destination = destination;
                meta->action = ONVM_NF_ACTION_TONF;
        }
        else {
                /* Drop real incoming packets */
                meta->action = ONVM_NF_ACTION_DROP;
//                onvm_pkt_print(pkt);
      //          s6a_generate_authentication_info_req_hss(pkt, meta);
		enb_ue_s1ap_id_p = (uint32_t *)((char*)pkt->buf_addr + pkt->data_off);
		printf("enb_ue_s1ap_id_p: %x\n", *enb_ue_s1ap_id_p);
		spoof_packets(CREATE_SESSION_RESP, 1, enb_ue_s1ap_id_p);
        }

#endif
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
#if 0
        struct rte_mempool *pktmbuf_pool;
        struct rte_mbuf* pkts[NUM_PKTS];
        int i;

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }
        printf("Creating %d packets to send to %d\n", NUM_PKTS, destination);
        for (i=0; i < NUM_PKTS; i++) {
                struct onvm_pkt_meta* pmeta;
                pkts[i] = rte_pktmbuf_alloc(pktmbuf_pool);
                pmeta = onvm_get_pkt_meta(pkts[i]);
                pmeta->destination = destination;
                pmeta->action = ONVM_NF_ACTION_TONF;
                pmeta->flags = ONVM_SET_BIT(0, SPEED_TESTER_BIT);
                pkts[i]->hash.rss = i;
                onvm_nflib_return_pkt(pkts[i]);
        }
#endif
        // spoof_packets();
        if (use_direct_rings) {
                run_advanced_rings();
        } else {
                onvm_nflib_run(nf_info, &packet_handler);
        }
        printf("If we reach here, program is ending\n");
        return 0;
}
