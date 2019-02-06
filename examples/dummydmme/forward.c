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
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <signal.h>
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

#define NF_TAG "simple_forward"
#define SPEED_TESTER_BIT 7
#define LOCATION_UPDATE_BIT 6
#define SGW_CREATE_SESSION 5

char IMSI_HTABLE[]={ "imsi_ue_context_htbl"};
char S11_HTABLE[] ={ "tun11_ue_context_htbl"};
char MME_HTABLE[] ={ "mme_ue_s1ap_id_ue_context_htbl"};
char ENB_HTABLE[] ={ "enb_ue_s1ap_id_ue_context_htbl"};
char GUTI_HTABLE[]={ "guti_ue_context_htbl"};

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

TAILQ_HEAD(, pkt_data_s) pkt_data_head;

/* number of package between each print */
static uint32_t print_delay = 1000000;

int childpid=0;
int attach_delay = 0;

static uint32_t destination;

void udelay(int useconds);

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


void udelay(int useconds)
{
	    long pause;
		clock_t now,then;

		pause = useconds*(CLOCKS_PER_SEC/1000000);
		now = then = clock();
		while( (now-then) < pause )
		now = clock();
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

        while ((c = getopt(argc, argv, "d:p:t:k:")) != -1) {
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
				case 't':
					attach_delay = strtoul(optarg, NULL, 10);
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

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf* pkt) {
        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
        static uint64_t pkt_process = 0;
        struct ipv4_hdr* ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("N°   : %"PRIu64"\n", pkt_process);
        printf("\n\n");

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found\n");
        }
}


int hex_to_num(char *hex, uint8_t *num_array)
{
    int len, i=0, num, j=0;
    char temp[2];

    len = strlen(hex);

    while(i+1 < len) {
        temp[0] = hex[i];
        temp[1] = hex[i+1];
        num = (uint8_t)strtol(temp, NULL, 16);
        i += 2;
        num_array[j++] = num;
    }
    return 0;

}

void frame_packet_for_sgw(struct rte_mbuf *packet, uint8_t * payload, uint32_t enb_ue_s1ap_id,
                          uint8_t msg_type, uint8_t slice_id)
{

#if SERVER_30
    struct ether_addr cfg_ether_src     =
        {{ 0x90, 0xe2, 0xba, 0x86, 0x7f, 0x91 }}; // 90:e2:ba:86:7f:91  port 1
    struct ether_addr cfg_ether_dst     =
        {{ 0xa0, 0x36, 0x9f, 0x10, 0xc6, 0x24 }}; // a0:36:9f:10:c6:24 .70
#else
    struct ether_addr cfg_ether_dst     =
        {{ 0x90, 0xe2, 0xba, 0x86, 0x7f, 0x91 }}; // 90:e2:ba:86:7f:91  port 1
    struct ether_addr cfg_ether_src     =
        {{ 0xa0, 0x36, 0x9f, 0x10, 0xc6, 0x24 }}; // a0:36:9f:10:c6:24 .70
#endif
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    ip_options_type * ip_opt;
    struct udp_hdr *udp_h;
    char * udp_data;
    pkt_identifier_t  pkt_identifier;

    eth_hdr = (struct ether_hdr *)rte_pktmbuf_append(packet, sizeof(struct ether_hdr));
    ether_addr_copy(&cfg_ether_dst,&(eth_hdr->d_addr));
    ether_addr_copy(&cfg_ether_src,&(eth_hdr->s_addr));
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    ipv4_hdr = (struct ipv4_hdr *)rte_pktmbuf_append(packet, sizeof(struct ipv4_hdr));
#if SERVER_30
    ipv4_hdr->src_addr=rte_cpu_to_be_32(IPv4(30,30,30,30));
    ipv4_hdr->dst_addr=rte_cpu_to_be_32(IPv4(30,30,30,35));
#else
    ipv4_hdr->dst_addr=rte_cpu_to_be_32(IPv4(30,30,30,30));
    ipv4_hdr->src_addr=rte_cpu_to_be_32(IPv4(30,30,30,35));
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

    ip_opt = (ip_options_type *)rte_pktmbuf_append(packet, sizeof(ip_options_type));

    memcpy(&ip_opt->ip_options[0], &enb_ue_s1ap_id, sizeof(uint32_t));
        /* Initialize UDP header. */
    udp_h = (struct udp_hdr *)rte_pktmbuf_append(packet, sizeof(struct udp_hdr));

    udp_h->src_port     = rte_cpu_to_be_16(23430);
    udp_h->dst_port     = rte_cpu_to_be_16(23430);
    udp_h->dgram_cksum  = 0; /* No UDP checksum. */
    udp_h->dgram_len    = rte_cpu_to_be_16(TXONLY_DEF_PACKET_LEN  -2 -
                                                   sizeof(pkt_identifier_t) -
                                                   sizeof(struct ether_hdr) -
                                                   sizeof(struct ipv4_hdr));

    udp_data= (char *)rte_pktmbuf_append(packet, TXONLY_DEF_PACKET_LEN -2 -
                           sizeof(pkt_identifier_t) -
                           sizeof(struct ether_hdr) -
                           sizeof(struct ipv4_hdr));

    pkt_identifier.slice_id = slice_id;
    pkt_identifier.msg_type = msg_type;

    memcpy(udp_data, &pkt_identifier, sizeof(pkt_identifier_t));

#if 1
        memcpy(udp_data + sizeof(pkt_identifier_t), payload, 
                            (TXONLY_DEF_PACKET_LEN - 2) -
                           sizeof(struct ether_hdr) -
                           sizeof(struct ipv4_hdr));
#endif
#if 0
        for(i = 0; i < 15; i++)
                printf("0x%x ", payload[i]);
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


}



void frame_packet_for_hss(struct rte_mbuf *packet, uint8_t * payload, 
                uint32_t enb_ue_s1ap_id, uint8_t msg_type, uint8_t slice_id)
{

#if SERVER_30
    struct ether_addr cfg_ether_src     =
        {{ 0x90, 0xe2, 0xba, 0x86, 0x7f, 0x91 }}; // 90:e2:ba:86:7f:91  port 1
    struct ether_addr cfg_ether_dst     =
        {{ 0xa0, 0x36, 0x9f, 0x10, 0xc6, 0x24 }}; // a0:36:9f:10:c6:24 .70
#else
    struct ether_addr cfg_ether_dst     =
        {{ 0x90, 0xe2, 0xba, 0x86, 0x7f, 0x91 }}; // 90:e2:ba:86:7f:91  port 1
    struct ether_addr cfg_ether_src     =
        {{ 0xa0, 0x36, 0x9f, 0x10, 0xc6, 0x24 }}; // a0:36:9f:10:c6:24 .70
#endif
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    ip_options_type * ip_opt;
    struct udp_hdr *udp_h;
    char * udp_data;
    pkt_identifier_t  pkt_identifier;

    eth_hdr = (struct ether_hdr *)rte_pktmbuf_append(packet, sizeof(struct ether_hdr));
    ether_addr_copy(&cfg_ether_dst,&(eth_hdr->d_addr));
    ether_addr_copy(&cfg_ether_src,&(eth_hdr->s_addr));
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    ipv4_hdr = (struct ipv4_hdr *)rte_pktmbuf_append(packet, sizeof(struct ipv4_hdr));
#if SERVER_30
    ipv4_hdr->src_addr=rte_cpu_to_be_32(IPv4(30,30,30,30));
    ipv4_hdr->dst_addr=rte_cpu_to_be_32(IPv4(30,30,30,35));
#else
    ipv4_hdr->dst_addr=rte_cpu_to_be_32(IPv4(30,30,30,30));
    ipv4_hdr->src_addr=rte_cpu_to_be_32(IPv4(30,30,30,35));
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

    ip_opt = (ip_options_type *)rte_pktmbuf_append(packet, sizeof(ip_options_type));

    memcpy(&ip_opt->ip_options[0], &enb_ue_s1ap_id, sizeof(uint32_t));
        /* Initialize UDP header. */
    udp_h = (struct udp_hdr *)rte_pktmbuf_append(packet, sizeof(struct udp_hdr));

    udp_h->src_port     = rte_cpu_to_be_16(23432);
    udp_h->dst_port     = rte_cpu_to_be_16(23432);
    udp_h->dgram_cksum  = 0; /* No UDP checksum. */
    udp_h->dgram_len    = rte_cpu_to_be_16(TXONLY_DEF_PACKET_LEN  -2 -
                                                   sizeof(pkt_identifier_t) -
                                                   sizeof(struct ether_hdr) -
                                                   sizeof(struct ipv4_hdr));

    udp_data= (char *)rte_pktmbuf_append(packet, TXONLY_DEF_PACKET_LEN -2 -
                           sizeof(pkt_identifier_t) -
                           sizeof(struct ether_hdr) -
                           sizeof(struct ipv4_hdr));

    pkt_identifier.slice_id = slice_id;
    pkt_identifier.msg_type = msg_type;

    memcpy(udp_data, &pkt_identifier, sizeof(pkt_identifier_t));

#if 1
        memcpy(udp_data + sizeof(pkt_identifier_t), payload, 
                            (TXONLY_DEF_PACKET_LEN - 2) -
                           sizeof(struct ether_hdr) -
                           sizeof(struct ipv4_hdr));
#endif
#if 0
        for(i = 0; i < 15; i++)
                printf("0x%x ", payload[i]);
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


}

void frame_packet(struct rte_mbuf *packet, uint8_t *payload, ue_context_t *ue_context) 
{

#if SERVER_30
    struct ether_addr cfg_ether_src	=
    	{{ 0x90, 0xe2, 0xba, 0x86, 0x7f, 0x90 }}; // 90:e2:ba:86:7f:90 port 0-30
    struct ether_addr cfg_ether_dst	=
    	{{ 0x90, 0xe2, 0xba, 0x86, 0x6f, 0x6d  }}; // 90:e2:ba:86:6f:6d UE
#else
    struct ether_addr cfg_ether_src     =
        {{ 0xa0, 0x36, 0x9f, 0x10, 0xc6, 0x26 }}; // a0:36:9f:10:c6:26 port 1-70
    struct ether_addr cfg_ether_dst     =
        {{ 0x90, 0xe2, 0xba, 0x86, 0x6f, 0x6c  }}; // 90:e2:ba:86:6f:6c UE
#endif
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
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
    ipv4_hdr->src_addr=rte_cpu_to_be_32(IPv4(10,10,10,30));
#else
    ipv4_hdr->src_addr=rte_cpu_to_be_32(IPv4(55,55,55,57));
#endif
    ipv4_hdr->dst_addr=(ue_context->src_ip);
//	ipv4_hdr->dst_addr=rte_cpu_to_be_32(IPv4(10,10,10,185));
    ipv4_hdr->version_ihl =IP_VHL_DEF;
	ipv4_hdr->type_of_service	= 0;
    ipv4_hdr->fragment_offset	= 0;
    ipv4_hdr->time_to_live	= IP_DEFTTL;
    ipv4_hdr->next_proto_id	= IPPROTO_UDP;
    ipv4_hdr->packet_id	= 30;
    ipv4_hdr->total_length	= rte_cpu_to_be_16((TXONLY_DEF_PACKET_LEN - 4) - sizeof( struct ether_hdr));
#ifdef IP_CKSUM_FIX
    ipv4_hdr->hdr_checksum = ip_sum((unaligned_uint16_t *)ipv4_hdr,
    						 sizeof(*ipv4_hdr));
#else
    ipv4_hdr->hdr_checksum = 0xd533;
#endif
	/* Initialize UDP header. */
    udp_h = (struct udp_hdr *)rte_pktmbuf_append(packet, sizeof(struct udp_hdr));

    udp_h->src_port	= rte_cpu_to_be_16(23432);
    udp_h->dst_port	= rte_cpu_to_be_16(ue_context->udp_port);
    udp_h->dgram_cksum	= 0; /* No UDP checksum. */
    udp_h->dgram_len	= rte_cpu_to_be_16((TXONLY_DEF_PACKET_LEN - 4) -
						   sizeof(struct ether_hdr) -
						   sizeof(struct ipv4_hdr));

    udp_data= (char *)rte_pktmbuf_append(packet, (TXONLY_DEF_PACKET_LEN - 4) -
			   sizeof(struct ether_hdr) -
			   sizeof(struct ipv4_hdr));

    memcpy(udp_data, payload, (TXONLY_DEF_PACKET_LEN - 4) -
                           sizeof(struct ether_hdr) -
                           sizeof(struct ipv4_hdr));
#ifdef LOGS
	for(i = 0; i < 15; i++)
		printf("0x%x ", payload[i]);
#endif

    packet->nb_segs		= 1;
    packet->pkt_len		= packet->data_len;
    packet->ol_flags		= 386;
    packet->vlan_tci		= 0;
    packet->vlan_tci_outer	= 0;
    packet->l2_len		= sizeof(struct ether_hdr);
    packet->l3_len		= sizeof(struct ipv4_hdr);


}

void frame_packet_debug(struct rte_mbuf *packet, uint8_t *payload, uint32_t udp_dest) 
{

    struct ether_addr cfg_ether_src	=
    	{{ 0x90, 0xe2, 0xba, 0x86, 0x7f, 0x90 }}; // 90:e2:ba:86:7f:90 port 0
    struct ether_addr cfg_ether_dst	=
    	{{ 0x90, 0xe2, 0xba, 0x86, 0x6f, 0x6d  }}; // 90:e2:ba:86:6f:6d UE
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct udp_hdr *udp_h;
//    char * udp_data;
	int i = 0;

    eth_hdr = onvm_pkt_ether_hdr(packet);
    ether_addr_copy(&cfg_ether_dst,&(eth_hdr->d_addr));
    ether_addr_copy(&cfg_ether_src,&(eth_hdr->s_addr));
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    ipv4_hdr = onvm_pkt_ipv4_hdr(packet);
    ipv4_hdr->src_addr=rte_cpu_to_be_32(IPv4(10,10,10,30));
    ipv4_hdr->dst_addr=rte_cpu_to_be_32(IPv4(10,10,10,185));
//    ipv4_hdr->dst_addr=rte_cpu_to_be_32(IPv4(10,10,10,185));
    ipv4_hdr->version_ihl =IP_VHL_DEF;
	ipv4_hdr->type_of_service	= 0;
    ipv4_hdr->fragment_offset	= 0;
    ipv4_hdr->time_to_live	= IP_DEFTTL;
    ipv4_hdr->next_proto_id	= IPPROTO_UDP;
    ipv4_hdr->packet_id	= 30;
    ipv4_hdr->total_length	= rte_cpu_to_be_16((TXONLY_DEF_PACKET_LEN - 4) - sizeof( struct ether_hdr));
    ipv4_hdr->hdr_checksum = ip_sum((unaligned_uint16_t *)ipv4_hdr,
    						 sizeof(*ipv4_hdr));

	/* Initialize UDP header. */
    udp_h = onvm_pkt_udp_hdr(packet);

    udp_h->src_port	= rte_cpu_to_be_16(23432);
    printf("Sending to port:%d  noths port:%d\n",udp_dest, ntohs(udp_dest));
    udp_h->dst_port	= rte_cpu_to_be_16(ntohs(udp_dest));
    udp_h->dgram_cksum	= 0; /* No UDP checksum. */
    udp_h->dgram_len	= rte_cpu_to_be_16((TXONLY_DEF_PACKET_LEN - 4) -
						   sizeof(struct ether_hdr) -
						   sizeof(struct ipv4_hdr));

#if 0
    udp_data= (char *)rte_pktmbuf_append(packet, (TXONLY_DEF_PACKET_LEN - 4) -
			   sizeof(struct ether_hdr) -
			   sizeof(struct ipv4_hdr));

#if 1
	memcpy(udp_data, payload, (TXONLY_DEF_PACKET_LEN - 4) -
                           sizeof(struct ether_hdr) -
                           sizeof(struct ipv4_hdr));
#endif
#endif
	for(i = 0; i < 15; i++)
		printf("0x%x ", payload[i]);

    packet->nb_segs		= 1;
    packet->pkt_len		= packet->data_len;
    packet->ol_flags		= 386;
    packet->vlan_tci		= 0;
    packet->vlan_tci_outer	= 0;
    packet->l2_len		= sizeof(struct ether_hdr);
    packet->l3_len		= sizeof(struct ipv4_hdr);


}


struct udp_hdr*
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


ip_options_type*
mme_pkt_ipopt_hdr(struct rte_mbuf* pkt) {
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

static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta)
{
	static uint32_t counter = 0;
	uint8_t* s1ap_pkt_data;
	uint8_t* s6a_pkt_data;
	uint8_t* s11_pkt_data;
	uint8_t procedure_code;
	struct ipv4_hdr *ip;
	struct udp_hdr  *udp;
	uint32_t s6_command_code=0;
	uint8_t s11_msg_type= 0;
	uint8_t ip_options_length = 0;
	uint8_t i;
	pkt_identifier_t    *pkt_identifier;
	bool is_perf_packet = 0;


	if (++counter == print_delay) {
		do_stats_display(pkt);
		counter = 0;
    }
	meta->action = ONVM_NF_ACTION_DROP;
	ip = onvm_pkt_ipv4_hdr(pkt);
	udp = mme_pkt_udp_hdr(pkt);

	if (ip != NULL) {
#ifdef LOGS
		if(ip->next_proto_id == 132) {
			RTE_LOG(INFO, APP, "sctp packet\n");
		} else if(ip->next_proto_id == 17) {
			RTE_LOG(INFO, APP, "udp packet\n");
		}
#endif
	} else {
			return -1;
	}
	if((ip->version_ihl&0x0f) > 5) {
                ip_options_length = ((ip->version_ihl&0x0f) - 5) * 32;
	}
	if (udp) {
		in_time = rte_rdtsc();//rte_get_tsc_hz();

		pkt_identifier =  (pkt_identifier_t*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(struct udphdr));
		if(pkt_identifier->msg_type == 0 && attach_delay)
		{
			udelay(attach_delay);
			//printf("delay of %d\n",attach_delay);
		}

		switch(udp->dst_port) {

		case S1AP_PORT:
			s1ap_pkt_data =  rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(pkt_identifier_t) + sizeof(struct udphdr);
			pkt_identifier =  (pkt_identifier_t*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(struct udphdr));



			if(s1ap_pkt_data == NULL)
				return -1;

#ifdef DEBUG_PACKET_SCALE_2
			frame_packet_debug(pkt, s1ap_pkt_data, udp->src_port);
			meta->destination = 0;
			meta->action = ONVM_NF_ACTION_OUT;
			return 0;
#endif

			procedure_code = *(s1ap_pkt_data + 1);
			switch(procedure_code){
				case 12:
					s1ap_mme_handle_initial_ue_message(pkt, pkt_identifier->slice_id);
					break;
				case 13:
					s1ap_mme_handle_uplink_nas_transport(pkt, pkt_identifier->msg_type, pkt_identifier->slice_id);
					break;
				case 9:
#ifdef LOGS
					RTE_LOG(INFO, APP, "\n\n\n");
					RTE_LOG(INFO, APP, "*************** Received Initial Context Setup Response ****************\n");
#endif
					s1ap_handle_initial_context_setup_response(pkt, pkt_identifier->msg_type, pkt_identifier->slice_id);
					break;
				case 23:
#ifdef LOGS
                                        RTE_LOG(INFO, APP, "\n\n\n");
                                        RTE_LOG(INFO, APP, "*************** Received UE Context Release Complete  ****************\n");
#endif
                                        break;
				default:
#ifdef LOGS
					RTE_LOG(INFO, APP, "*************** Unknown message type received ****************\n");
#endif
					break;

			}
			goto exit_pkt_processed;

		case S6A_PORT:
			s6a_pkt_data = rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(pkt_identifier_t) + sizeof(struct udphdr);

			pkt_identifier =  (pkt_identifier_t*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(struct udphdr));

			if(s6a_pkt_data == NULL)
				return 0;

			for(i = 0; i < 3; i++)
				s6_command_code = s6_command_code*256 + *(uint8_t*)(s6a_pkt_data + 5 + i);

			switch(s6_command_code){

				case S6A_AUTH_INFO:
#ifdef LOGS
					RTE_LOG(INFO, APP, "\n\n\n");
					RTE_LOG(INFO, APP, "*************** UE Authentication parameters received from HSS ****************\n");
#endif
					s6a_generate_authentication_info_req(pkt);
					break;

				case S6A_LAU:
#ifdef LOGS
					RTE_LOG(INFO, APP, "\n\n\n");
					RTE_LOG(INFO, APP, "*************** LOCATION UPDATE response received from HSS ****************\n");
#endif
					s11_handle_location_update_response(pkt, pkt_identifier->msg_type, pkt_identifier->slice_id);
					break;
				default:
#ifdef LOGS
					RTE_LOG(INFO, APP, "\n\n\n");
					RTE_LOG(INFO, APP, " Error... No valid command code found.. : %d\n", s6_command_code);
#endif
					break;

			}

			goto exit_pkt_processed;
			break;

		case S11_PORT:
			s11_pkt_data = rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(pkt_identifier_t) + sizeof(struct udphdr);
			if(s11_pkt_data == NULL)
				return 0;
			s11_msg_type = * (s11_pkt_data+1);
#ifdef LOGS
			RTE_LOG(INFO, APP, "s11_msg_type : %d\n", s11_msg_type);
#endif

			switch(s11_msg_type){

				case S11_CREATE_SESSION_RSP:
#ifdef LOGS
					RTE_LOG(INFO, APP, "\n\n\n");
					RTE_LOG(INFO, APP, "*************** CREATE SESSION RESPONSE received from SGW  ****************\n");
#endif
					s11_handle_create_session_resp(pkt);
					break;

				case S11_MODIFY_BEARER_RSP:
#ifdef LOGS
					RTE_LOG(INFO, APP, "\n\n\n");
					RTE_LOG(INFO, APP, "*************** MODIFY BEARER RESPONSE received from SGW  ****************\n");
#endif
					break;

				case S11_DELETE_SESSION_RSP:
#ifdef LOGS
						RTE_LOG(INFO, APP, "\n\n\n");
						RTE_LOG(INFO, APP, "*************** DELETE SESSION RESPONSE received from SGW  ****************\n");
#endif
						s11_handle_delete_session_resp(pkt);
						break;

			}
			break;
			/*
			 * If it is a start or end test packet,
			 * then forward it to perf_monitor NF
			 */
		case EXP_START_PORT:
		case EXP_STOP_PORT:
			is_perf_packet = 1;
			break;
		default:
			RTE_LOG(INFO, APP, "Unknown port!! : %d\n", udp->dst_port);
			break;
		}/*end switch(udp->dst_port)*/
	}/* end if udp */

	if (is_perf_packet) {
        meta->destination = 5;
        meta->action = ONVM_NF_ACTION_TONF;
	} else {
        meta->action = ONVM_NF_ACTION_DROP;
        meta->destination = destination;
	}
exit_pkt_processed:
        return 0;
}


int main(int argc, char *argv[])
{
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
