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
#include <rte_udp.h>
#include <rte_byteorder.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "speed"

#define NUM_PKTS 32
#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define PKT_READ_SIZE  ((uint16_t)32)
#define TXONLY_DEF_PACKET_LEN 64

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)


/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 10000000;
static uint16_t destination;
static uint8_t use_direct_rings = 0;
static uint8_t keep_running = 1;

struct rte_mempool *pktmbuf_pool;



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

static void print_mac(struct ether_addr A) {
	printf("%x:%x:%x:%x:%x:%x\n",A.addr_bytes[0] ,A.addr_bytes[1] ,A.addr_bytes[2] ,A.addr_bytes[3] ,A.addr_bytes[4] ,A.addr_bytes[5] );
}

static void print_pkt(struct rte_mbuf *packet) {
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    //struct udp_hdr *udp_h;

    printf("\n buf_physaddr:%ld",packet->buf_physaddr);
    printf("\n buf_len:%d",packet->buf_len);
    printf("\n data_off:%d",packet->data_off);
    printf("\n nb_segs:%d",packet->nb_segs);
    printf("\n port:%d",packet->port);
    printf("\n ol_flags:%lu",packet->ol_flags);
    printf("\n pkt_len:%u",packet->pkt_len);
    printf("\n data_len:%d",packet->data_len);
    printf("\n vlan_tci:%d",packet->vlan_tci);
    printf("\n seqn:%u",packet->seqn);
    printf("\n vlan_tci_outer:%d",packet->vlan_tci_outer);
    printf("\n priv_size:%d",packet->priv_size);
    printf("\n timesync:%d\n",packet->timesync);


	if((eth_hdr = onvm_pkt_ether_hdr(packet))) {
		printf("Dest:");
		print_mac(eth_hdr->d_addr);
		printf("Src:");
		print_mac(eth_hdr->s_addr);
		printf("proto:%u\n", eth_hdr->ether_type);

		if((ipv4_hdr = onvm_pkt_ipv4_hdr(packet))) {
			printf("version_ihl:%u\n",ipv4_hdr->version_ihl);
			//uint8_t  version_ihl;		/**< version and header length */
			printf("type_of_service:%u\n",ipv4_hdr->type_of_service);
			//uint8_t  type_of_service;	/**< type of service */
			printf("total_length:%u\n",ipv4_hdr->total_length);
			//uint16_t total_length;		/**< length of packet */
			printf("packet_id:%u\n",ipv4_hdr->packet_id);
			//uint16_t packet_id;		/**< packet ID */
			printf("fragment_offset:%u\n",ipv4_hdr->fragment_offset);
			//uint16_t fragment_offset;	/**< fragmentation offset */
			printf("time_to_live:%u\n",ipv4_hdr->time_to_live);
			//uint8_t  time_to_live;		/**< time to live */
			printf("next_proto_id:%u\n",ipv4_hdr->next_proto_id);
			//uint8_t  next_proto_id;		/**< protocol ID */
			printf("hdr_checksum:%u\n",ipv4_hdr->hdr_checksum);
			//uint16_t hdr_checksum;		/**< header checksum */
			printf("src_addr:%u\n",ipv4_hdr->src_addr);
			//uint32_t src_addr;		/**< source address */
			printf("dst_addr:%u\n",ipv4_hdr->dst_addr);
			//uint32_t dst_addr;		/**< destination address */

		}
		printf("\n");
	}

}

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

        while ((c = getopt (argc, argv, "d:p:a:")) != -1) {
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

static void frame_packet(struct rte_mbuf *packet) {

    struct ether_addr cfg_ether_src	=
    	{{ 0xa0, 0x36, 0x9f, 0x10, 0xc6, 0x26 }};
    struct ether_addr cfg_ether_dst	=
    	{{ 0x00, 0x0f, 0x53, 0x0d, 0x76, 0x60 }};
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct udp_hdr *udp_h;
    char * udp_data;


    eth_hdr = (struct ether_hdr *)rte_pktmbuf_append(packet, sizeof(struct ether_hdr));
    ether_addr_copy(&cfg_ether_dst,&(eth_hdr->d_addr));
    ether_addr_copy(&cfg_ether_src,&(eth_hdr->s_addr));
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    ipv4_hdr = (struct ipv4_hdr *)rte_pktmbuf_append(packet, sizeof(struct ipv4_hdr));
    ipv4_hdr->src_addr=rte_cpu_to_be_32(IPv4(5,5,5,6));
    ipv4_hdr->dst_addr=rte_cpu_to_be_32(IPv4(5,5,5,5));
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
    udp_h = (struct udp_hdr *)rte_pktmbuf_append(packet, sizeof(struct udp_hdr));

    udp_h->src_port	= rte_cpu_to_be_16(23432);
    udp_h->dst_port	= rte_cpu_to_be_16(23432);
    udp_h->dgram_cksum	= 0; /* No UDP checksum. */
    udp_h->dgram_len	= rte_cpu_to_be_16((TXONLY_DEF_PACKET_LEN - 4) -
						   sizeof(struct ether_hdr) -
						   sizeof(struct ipv4_hdr));

    udp_data= (char *)rte_pktmbuf_append(packet, (TXONLY_DEF_PACKET_LEN - 4) -
			   sizeof(struct ether_hdr) -
			   sizeof(struct ipv4_hdr));

    strncpy(udp_data,"Fire on the mountain\r\n",(TXONLY_DEF_PACKET_LEN - 4) -
			   sizeof(struct ether_hdr) -
			   sizeof(struct ipv4_hdr));

    packet->nb_segs		= 1;
    packet->pkt_len		= packet->data_len;
    packet->ol_flags		= 386;
    packet->vlan_tci		= 0;
    packet->vlan_tci_outer	= 0;
    packet->l2_len		= sizeof(struct ether_hdr);
    packet->l3_len		= sizeof(struct ipv4_hdr);


}

static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
        static uint32_t counter = 0;static int flag = 0;
        struct rte_mbuf* sample_pkt;

        if (counter++ == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }

        if(pkt->port == 1) {
                /* one of our fake pkts to forward */
                meta->destination = 0;
                meta->action = ONVM_NF_ACTION_OUT;
        }
        else if (pkt->port == 0){
                /* Drop real incoming packets */
        		meta->destination = 1;
                meta->action = ONVM_NF_ACTION_OUT;
                if(flag == 0) {
                    sample_pkt = rte_pktmbuf_alloc(pktmbuf_pool);
                    frame_packet(sample_pkt);
                    printf("Sample Packet\n");
                    print_pkt(sample_pkt);
                    printf("Packet\n");
                    print_pkt(pkt);
                    flag = 1;
                }
        }
        else {
        	meta->action = ONVM_NF_ACTION_DROP;
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
                pmeta->destination = 1;
                pmeta->action = ONVM_NF_ACTION_OUT;
                frame_packet(pkts[i]);
                pkts[i]->port = 1;
                //pkts[i]->hash.rss = i;
                onvm_nflib_return_pkt(pkts[i]);
        }

        if (use_direct_rings) {
                run_advanced_rings();
        } else {
                onvm_nflib_run(nf_info, &packet_handler);
        }
        printf("If we reach here, program is ending\n");
        return 0;
}
