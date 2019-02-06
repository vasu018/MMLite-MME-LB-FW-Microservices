#ifndef HSS_H
#define HSS_H

#include "s6a.h"
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


#define SERVER_30 1

#if SERVER_30
        #define MME_PORT 1
#else
        #define MME_PORT 0
#endif

#define CREATE_PACKET_AUTH              1
#define CREATE_PACKET_LOCATION_UPDATE   2

#define NF_TAG "speed"

#define NUM_PKTS 128
#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define PKT_READ_SIZE  ((uint16_t)32)
#define SPEED_TESTER_BIT 7
#define LOCATION_UPDATE_BIT 6
#define MAX_BUF_LEN 1024

#define MME_LOC_UPDATE_GET_PDN              0x01
#define MME_LOC_UPDATE_USR_UPDATE_RAND_SQN  0x02
#define MME_LOC_UPDATE_USR_UPDATE_SQN       0x03
#define MME_LOC_UPDATE_GET_USR_DATA         0x04
#define MME_LOC_UPDATE_GET_MMEID            0x05
#define MME_AUTH_REQ                        0x06

#define TXONLY_DEF_PACKET_LEN 256

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_HDRLEN_HSS  0x06
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define IP_VHL_DEF_HSS (IP_VERSION | IP_HDRLEN_HSS)




typedef struct{
	uint8_t rand[16];
	uint8_t ak[6];
	uint8_t seq[6];
}auth_params_t;

typedef struct pkt_identifier_s {
    uint8_t slice_id;
    uint8_t msg_type;
}pkt_identifier_t;

typedef struct {
        uint8_t ip_options[32];
}ip_options_type;

ip_options_type* hss_pkt_ipopt_hdr(struct rte_mbuf* pkt);

int frame_packet_for_hss(struct rte_mbuf *packet, uint8_t * payload, 
			uint32_t enb_ue_s1ap_id, pkt_identifier_t *pkt_identifier);

#endif
