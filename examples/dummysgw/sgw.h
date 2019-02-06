#ifndef SGW_H
#define SGW_H

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

#define CREATE_SESSION_RESP              1

#define TXONLY_DEF_PACKET_LEN 256

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_HDRLEN_HSS  0x06
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define IP_VHL_DEF_HSS (IP_VERSION | IP_HDRLEN_HSS)


#define S11_CREATE_SESSION_REQ		0x20
#define S11_MODIFY_BEARER_REQ		0x22
#define S11_DELETE_SESSION_REQ           0x24
#define S11_DELETE_SESSION_RSP           0x25



typedef struct pkt_identifier_s {
    uint8_t slice_id;
    uint8_t msg_type;
}pkt_identifier_t;


typedef struct {
        uint8_t ip_options[32];
}ip_options_type;

ip_options_type* sgw_pkt_ipopt_hdr(struct rte_mbuf* pkt);

int frame_packet_from_sgw(struct rte_mbuf *packet, uint8_t * payload, 
                           uint32_t enb_ue_s1ap_id, uint8_t msg_type, uint8_t slice_id);




#endif
