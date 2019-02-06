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

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include <rte_ether.h>
#include <rte_ethdev.h>
#include "mme.h"
#include "mme_context.h"

#define NF_TAG "simple_forward"

int
//s11_handle_location_update_response(struct rte_mbuf* pkt){
s11_handle_location_update_response(struct rte_mbuf* pkt, uint8_t msg_type, uint8_t slice_id)
{
//        s11_send_create_session_req(&imsi_g[0]);
	uint32_t enb_ue_s1ap_id;
	ip_options_type* ip_opt;
        ue_context_t * ue_context;

        ip_opt= mme_pkt_ipopt_hdr(pkt);
        if(ip_opt == NULL)
                RTE_LOG(INFO, APP, "ERROR: enb_ue_s1ap_id not present");
        else
                memcpy(&enb_ue_s1ap_id, &ip_opt->ip_options[0], sizeof(uint32_t));

        ue_context = kvs_get(ENB_HTABLE,enb_ue_s1ap_id);
        if(!ue_context) {
            RTE_LOG(ERR, APP, "\nContext not found for enb ID:%x\n",enb_ue_s1ap_id);
            return -1;
        }
	ue_context->conn_state = UE_STATE_ATTACH_LOCATION_UPDATE;
#ifdef TIME_STATS
	ue_context->time_stamp[INDEX_ATTACH_LOCATION_UPDATE_RSP_IN] = in_time;
#endif
#ifdef LOGS
	printf("\nenb_ue_s1ap_id = 0x%x \n", enb_ue_s1ap_id);
#endif
	s11_send_create_session_req(enb_ue_s1ap_id, msg_type, slice_id);

	return 0;
}


int
s11_handle_create_session_resp(struct rte_mbuf* pkt)
{
//        s11_send_create_session_req(&imsi_g[0]);
        uint32_t enb_ue_s1ap_id;
        ip_options_type* ip_opt;
        ue_context_t * ue_context;

        ip_opt= mme_pkt_ipopt_hdr(pkt);
        if(ip_opt == NULL)
                RTE_LOG(INFO, APP, "ERROR: enb_ue_s1ap_id not present");
        else
                memcpy(&enb_ue_s1ap_id, &ip_opt->ip_options[0], sizeof(uint32_t));

        ue_context = kvs_get(ENB_HTABLE,enb_ue_s1ap_id);
        if(!ue_context) {
            RTE_LOG(ERR, APP, "\nContext not found for enb ID:%x\n",enb_ue_s1ap_id);
            return -1;
        }
	ue_context->conn_state = UE_STATE_ATTACH_CREATE_SESSION;

	
#ifdef TIME_STATS
        ue_context->time_stamp[INDEX_ATTACH_CREATE_SESSION_IN] = in_time;
#endif
#ifdef LOGS
        printf("\nenb_ue_s1ap_id = 0x%x \n", enb_ue_s1ap_id);
#endif
	nas_itti_establish_cnf(enb_ue_s1ap_id);
        return 0;
}



//int s11_send_create_session_req(uint8_t * imsi){
int s11_send_create_session_req(uint32_t enb_ue_s1ap_id, uint8_t msg_type, uint8_t slice_id)
{
        struct rte_mbuf* create_ses_req;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = {0x48, 0x20, 0x00, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x40, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x98, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x52, 0x00, 0x01, 0x00, 0x06, 0x63, 0x00, 0x01, 0x00, 0x01, 0x57, 0x00, 0x09, 0x00, 0x8a, 0x00, 0x00, 0x02, 0x00, 0x7f, 0x00, 0x0b, 0x01, 0x57, 0x00, 0x05, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x09, 0x00, 0x03, 0x6f, 0x61, 0x69, 0x04, 0x69, 0x70, 0x76, 0x34, 0x53, 0x00, 0x03, 0x00, 0x02, 0xf8, 0x39, 0x4e, 0x00, 0x1a, 0x00, 0x80, 0x80, 0x21, 0x10, 0x01, 0x00, 0x00, 0x10, 0x81, 0x06, 0x00, 0x00, 0x00, 0x00, 0x83, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x08, 0x00, 0x00, 0x5d, 0x00, 0x1f, 0x00, 0x49, 0x00, 0x01, 0x00, 0x05, 0x50, 0x00, 0x16, 0x00, 0x7c, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#ifdef TIME_STATS
        ue_context_t * ue_context;

        ue_context = kvs_get(ENB_HTABLE,enb_ue_s1ap_id);
        if(!ue_context) {
            RTE_LOG(ERR, APP, "\nContext not found for enb ID:%x\n",enb_ue_s1ap_id);
            return -1;
        }
#endif

	
       // packet[0] = PACKET_ID_ATTACH_ACCEPT;

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        create_ses_req = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(create_ses_req);
        pmeta->destination = 1;
        pmeta->action = ONVM_NF_ACTION_OUT;

#ifdef LOGS
        printf("enb_ue_s1ap_id = %x", enb_ue_s1ap_id);
#endif
//        ue_context = kvs_get(ENB_HTABLE, enb_ue_s1ap_id);

	frame_packet_for_sgw(create_ses_req, &packet[0], enb_ue_s1ap_id, msg_type, slice_id);
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "*************** CREATE SESSION REQUEST sent to SGW ****************\n");
#endif
#ifdef TIME_STATS
       ue_context->time_stamp[INDEX_ATTACH_CREATE_SESSION_OUT] = rte_rdtsc();//rte_get_tsc_hz();
#endif
        onvm_nflib_return_pkt(create_ses_req);
        return 0;

}




int
s11_send_modify_bearer_req(uint32_t enb_ue_s1ap_id, uint8_t msg_type, uint8_t slice_id)
{
        struct rte_mbuf* create_ses_req;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
//	ue_context_type ue_context;
        uint8_t packet[] = {0x48, 0x20, 0x00, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x40, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x98, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x52, 0x00, 0x01, 0x00, 0x06, 0x63, 0x00, 0x01, 0x00, 0x01, 0x57, 0x00, 0x09, 0x00, 0x8a, 0x00, 0x00, 0x02, 0x00, 0x7f, 0x00, 0x0b, 0x01, 0x57, 0x00, 0x05, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x09, 0x00, 0x03, 0x6f, 0x61, 0x69, 0x04, 0x69, 0x70, 0x76, 0x34, 0x53, 0x00, 0x03, 0x00, 0x02, 0xf8, 0x39, 0x4e, 0x00, 0x1a, 0x00, 0x80, 0x80, 0x21, 0x10, 0x01, 0x00, 0x00, 0x10, 0x81, 0x06, 0x00, 0x00, 0x00, 0x00, 0x83, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x08, 0x00, 0x00, 0x5d, 0x00, 0x1f, 0x00, 0x49, 0x00, 0x01, 0x00, 0x05, 0x50, 0x00, 0x16, 0x00, 0x7c, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#ifdef TIME_STATS
        ue_context_t * ue_context;

        ue_context = kvs_get(ENB_HTABLE,enb_ue_s1ap_id);
        if(!ue_context) {
            RTE_LOG(ERR, APP, "\nContext not found for enb ID:%x\n",enb_ue_s1ap_id);
            return -1;
        }
#endif


        packet[1] = S11_MODIFY_BEARER_REQ;

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }


/*
	if (ue_context->conn_state < UE_STATE_SERVICE_REQ) {
            printf("\nSetting state to be ATTACH NAS\n");
            ue_context->conn_state = UE_STATE_ATTACH_NAS_SECURITY_REQ;
        }
*/
        create_ses_req = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(create_ses_req);
        pmeta->destination = 1;
        pmeta->action = ONVM_NF_ACTION_OUT;

#ifdef LOGS
        printf("enb_ue_s1ap_id = %x", enb_ue_s1ap_id);
#endif
//        ue_context = kvs_get(ENB_HTABLE, enb_ue_s1ap_id);

        frame_packet_for_sgw(create_ses_req, &packet[0], enb_ue_s1ap_id, msg_type, slice_id);
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "*************** MODIFY BEARER REQUEST sent to SGW ****************\n");
#endif
#ifdef TIME_STATS
             ue_context->time_stamp[INDEX_ATTACH_MODIFY_BEARER_OUT] = rte_rdtsc();//rte_get_tsc_hz();
#endif

        onvm_nflib_return_pkt(create_ses_req);
        return 0;
}
