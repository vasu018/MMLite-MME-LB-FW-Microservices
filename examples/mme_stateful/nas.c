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
#include <rte_ether.h>
#include <rte_ethdev.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "mme.h"
#include "kvs_main.h"

/*decode nas message here*/
int nas_message_decode(nas_pdu_type* nas_pdu, uint8_t * nas_pdu_buf)
{
	uint8_t* imsi_p;
//        int i;
        int j;

	nas_pdu->security_header_type = ((*nas_pdu_buf) & 0xf0) >> 4;
	if (nas_pdu->security_header_type == 4 ||nas_pdu->security_header_type == 2 )
	{
		nas_pdu_buf += 6;
		nas_pdu->security_header_type = ((*nas_pdu_buf) & 0xf0) >> 4;
	}        

	nas_pdu->protocol_discriminator = ((*nas_pdu_buf) & 0x0f);
        nas_pdu->MM_message_type = *(nas_pdu_buf + 1);
        switch(nas_pdu->MM_message_type){

        case 0x41:

	        nas_pdu->MM_message.attach_req.security_context = (*(nas_pdu_buf + 2) & 0x80) >> 7;
	        nas_pdu->MM_message.attach_req.NAS_key_set_id = (*(nas_pdu_buf + 2) & 0x70) >> 4;
	        nas_pdu->MM_message.attach_req.attach_type = (*(nas_pdu_buf + 2) & 0x07);
	        nas_pdu->MM_message.attach_req.EPS_id.length = *(nas_pdu_buf + 3);
	        nas_pdu->MM_message.attach_req.EPS_id.odd_even = (*(nas_pdu_buf + 4) & 0x08) >> 3;
	        nas_pdu->MM_message.attach_req.EPS_id.id_type = *(nas_pdu_buf + 4) & 0x07;
	        imsi_p = nas_pdu_buf + 4;
		memcpy(&nas_pdu->MM_message.attach_req.EPS_id.imsi, imsi_p, sizeof(uint64_t));
	        for(j = 0; j < 15; j++)
	        {
		        if(j % 2 == 0)
	        	{
                        	nas_pdu->MM_message.attach_req.EPS_id.identity[j] = (*imsi_p & 0xf0) >> 4;
	                        imsi_p++;
        	        }
	                else
	                        nas_pdu->MM_message.attach_req.EPS_id.identity[j] = (*imsi_p & 0x0f);
//			imsi_g[j] = nas_pdu->MM_message.attach_req.EPS_id.identity[j];

	        }
	        
                nas_pdu->MM_message.attach_req.EPS_id.identity[15] = '\0';
	        nas_pdu->MM_message.attach_req.network_capability.length = *(nas_pdu_buf + 12);
	        //printf("IMSI = %s", nas_pdu->EPS_id.identity);
#ifdef LOGS
	        for(j = 0; j < 15; j++)
	                RTE_LOG(INFO, APP, "IMSI = %x \n", nas_pdu->MM_message.attach_req.EPS_id.identity[j]);
		RTE_LOG(INFO, APP, "IMSI = %lx \n", nas_pdu->MM_message.attach_req.EPS_id.imsi);
#endif
	        break;

        case 0x53:
                nas_pdu->MM_message.auth_resp.length = *(nas_pdu_buf + 2);
                memcpy(&nas_pdu->MM_message.auth_resp.auth_resp[0],nas_pdu_buf + 3, nas_pdu->MM_message.auth_resp.length);
#ifdef LOGS
	        for(j = 0; j < nas_pdu->MM_message.auth_resp.length; j++)
	     	        RTE_LOG(INFO, APP, "Auth res = 0x%x \n", nas_pdu->MM_message.auth_resp.auth_resp[j]);
#endif
	        break;

	case 0x5E:
		break;
		
	case 0x43:
		break;
		
        default:
                break;
	}

	return 0;
}

int 
nas_encode_auth_req(uint8_t* rand, uint8_t* autn, uint32_t enb_ue_s1ap_id){
	struct rte_mbuf* auth_req;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = {0x03 , 0x0b ,0x00 , 0x3a, 0x00, 0x00, 0x03 , 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x08, 0x00, 0x04, 0x80, 0x64, 0x6d, 0xbe, 0x00, 0x1a, 0x00, 0x25, 0x24, 0x07, 0x52, 0x00, 0xc0, 0xdf, 0x4d, 0x06, 0x89, 0x87, 0xa9, 0x4b, 0x91, 0xa1, 0x71, 0x08, 0xf8, 0x3e, 0xb6, 0x02, 0x10, 0xb6, 0xad, 0x0a, 0x37, 0xe4, 0x06, 0x80, 0x00, 0x33, 0x5b, 0x5b, 0x63, 0xba, 0x25, 0x5d, 0x81};
        //struct ipv4_hdr* ipv4 = (struct ipv4_hdr*)(&packet[0] + sizeof(struct ether_hdr));
        uint32_t * enb_ue_s1ap_id_p = (uint32_t *)(&packet[0] + 17);
	uint8_t * rand_p = &packet[0] + 29;
        uint8_t * autn_p = rand + 17;
//	int i;
	ue_context_t * ue_context;


        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }
        
        packet[0] = PACKET_ID_AUTH_REQ;

        auth_req = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(auth_req);
        pmeta->destination = UE_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;

	//ipv4->src_addr = IPv4(130,245,144,70);
        //ipv4->dst_addr = IPv4(130,245,144,30);
	memcpy(rand_p, rand, 16);
	memcpy(autn_p, autn, 16);

	memcpy(enb_ue_s1ap_id_p, &enb_ue_s1ap_id, sizeof(uint32_t));
	

	ue_context = kvs_get(ENB_HTABLE, enb_ue_s1ap_id);

	if(ue_context == NULL)
		rte_exit(EXIT_FAILURE, "UE context not found!\n");
#ifdef LOGS
	RTE_LOG(INFO, APP, "UDP port = 0x%x \n", ue_context->udp_port);
	RTE_LOG(INFO, APP, "UDP port = 0x%x \n", ntohs(ue_context->udp_port));
#endif
        /*
         * Set state to auth req since we are sending to UE for auth check
         * Check previous state and set accordingly
         */
        if (ue_context->conn_state < UE_STATE_SERVICE_REQ) {
#ifdef LOGS
            printf("\nSetting state to be ATTACH AUTH REQ\n");
#endif
            ue_context->conn_state = UE_STATE_ATTACH_AUTH_REQ;
        } else {
#ifdef LOGS
            printf("\nSetting state to be SERVICE AUTH REQ\n");
#endif
            ue_context->conn_state = UE_STATE_SERVICE_AUTH_REQ;
        }

	frame_packet(auth_req, &packet[0], ue_context);
#ifdef LOGS
	RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "*************** Authentication request sent to UE ****************\n");
#endif
//        RTE_LOG(INFO, APP, "ip = %o.%o.%o.%o \n", packet[26],packet[27],packet[28],packet[29] );

#ifdef TIME_STATS
	if (ue_context->conn_state < UE_STATE_SERVICE_REQ) {      
        	ue_context->time_stamp[INDEX_ATTACH_AUTH_REQ_OUT] = rte_rdtsc();//rte_get_tsc_hz();
	}
#endif

	onvm_nflib_return_pkt(auth_req);
	return 0;
}

int
nas_encode_security_command(uint32_t enb_ue_s1ap_id){
        struct rte_mbuf* seq_command;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = { 0x02, 0x0b, 0x00, 0x23, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x08, 0x00, 0x04, 0x80, 0x64, 0x6d, 0xbe, 0x00, 0x1a, 0x00, 0x0e, 0x0d, 0x37, 0x5f, 0x28, 0x8b, 0x28, 0x00, 0x07, 0x5d, 0x02, 0x00, 0x02, 0x80, 0x20, 0x00};
	uint32_t * enb_ue_s1ap_id_p = (uint32_t *)(&packet[0] + 17);
	ue_context_t * ue_context;

        packet[0] = PACKET_ID_NAS_SEC_REQ;
	//struct ipv4_hdr* ipv4 = (struct ipv4_hdr*)(&packet[0] + sizeof(struct ether_hdr));
        //uint8_t * rand_p = &packet[0] + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 44 + 29;
        //uint8_t * sqn_ak_p = rand + 18;
        //int i;

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        seq_command = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(seq_command);
        pmeta->destination = UE_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;

        //ipv4->src_addr = IPv4(130,245,144,70);
        //ipv4->dst_addr = IPv4(130,245,144,30);
#if 0        
	memcpy(rand, rand_p, 16);
        for(i = 0; i < 6; i++)
                *(sqn_ak_p + i) = sqn[i]^ak[i];


        RTE_LOG(INFO, APP, "ip = %o.%o.%o.%o \n", packet[26],packet[27],packet[28],packet[29] );
#endif

	memcpy(enb_ue_s1ap_id_p, &enb_ue_s1ap_id, sizeof(uint32_t));

        ue_context = kvs_get(ENB_HTABLE, enb_ue_s1ap_id);
	
        if(ue_context == NULL)
		rte_exit(EXIT_FAILURE, "UE context not found!\n");
        
        if (ue_context->conn_state < UE_STATE_SERVICE_REQ) {
#ifdef LOGS
            printf("\nSetting state to be ATTACH NAS\n");
#endif
            ue_context->conn_state = UE_STATE_ATTACH_NAS_SECURITY_REQ;
        } else {
#ifdef LOGS
            printf("\nSetting state to be SERVICE NAS\n");
#endif
            ue_context->conn_state = UE_STATE_SERVICE_NAS_SECURITY_REQ;
        }

	frame_packet(seq_command, &packet[0], ue_context);
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "*************** NAS security request sent to UE ****************\n");
#endif

#ifdef TIME_STATS
        if (ue_context->conn_state < UE_STATE_SERVICE_REQ) {
                ue_context->time_stamp[INDEX_ATTACH_NAS_SECURITY_REQ_OUT] = rte_rdtsc();//rte_get_tsc_hz();
        }
#endif
        onvm_nflib_return_pkt(seq_command);
        return 0;
}

/*create message to UE here :  NAS security setup request, Auth request*/
int
nas_message_encode(message_id_type msg_id, void * message, uint32_t enb_ue_s1ap_id){
//	uint8_t* packet;
	switch(msg_id) {
		case NAS_SECURITY_REQ:
			nas_encode_security_command(enb_ue_s1ap_id);
			break;
		case NAS_AUTHENTICATION_REQ:
//			packet = (uint8_t *) malloc(142);
			nas_encode_auth_req(((auth_params_type *)message)->rand,((auth_params_type *)message)->autn, enb_ue_s1ap_id);
			break;
		default:
			break;
	}

	s1ap_generate_downlink_nas_transport();
//	if(packet != NULL)
//		free(packet);
	return 0;
}

/*initial UE message is handled here. called from s1ap*/
int
nas_proc_establish_ind(uint8_t * imsi, uint32_t enb_ue_s1ap_id, uint8_t  msg_type, uint8_t slice_id)
{
        struct rte_mbuf* auth_req;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = {0x01, 0x00, 0x01 , 0x24 , 0xc0 , 0x00, 0x01, 0x3e, 0x01, 0x00, 0x00, 0x23, 0x23, 0x2e, 0xcf, 0xd5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x40, 0x00, 0x00, 0x38, 0x76, 0x61, 0x73, 0x75, 0x64, 0x65, 0x76, 0x61, 0x6e, 0x65, 0x70, 0x63, 0x32, 0x2e, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x3b, 0x31, 0x34, 0x39, 0x30, 0x36, 0x37, 0x37, 0x37, 0x37, 0x35, 0x3b, 0x31, 0x3b, 0x61, 0x70, 0x70, 0x73, 0x36, 0x61, 0x00, 0x00, 0x01, 0x15, 0x40, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x24, 0x76, 0x61, 0x73, 0x75, 0x64, 0x65, 0x76, 0x61, 0x6e, 0x65, 0x70, 0x63, 0x32, 0x2e, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x28, 0x40, 0x00, 0x00, 0x16, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x00, 0x00, 0x00, 0x00, 0x01, 0x25, 0x40, 0x00, 0x00, 0x24, 0x76, 0x61, 0x73, 0x75, 0x64, 0x65, 0x76, 0x61, 0x6e, 0x65, 0x70, 0x63, 0x32, 0x2e, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x1b, 0x40, 0x00, 0x00, 0x16, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x17, 0x32, 0x30, 0x38, 0x39, 0x33, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x00, 0x00, 0x00, 0x05, 0x7f, 0xc0, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x28, 0xaf, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x05, 0x80, 0xc0, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x05, 0x82, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x05, 0x84, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x00};
        //struct ipv4_hdr* ipv4 = (struct ipv4_hdr*)(&packet[0] + sizeof(struct ether_hdr));
        int i;
//        ue_context_t * ue_context;
	uint8_t * imsi_p =&packet[0] + 216;

        ue_context_t * ue_context;

        ue_context = kvs_get(ENB_HTABLE,enb_ue_s1ap_id);
        if(!ue_context) {
            RTE_LOG(ERR, APP, "\nContext not found for enb ID:%x\n",enb_ue_s1ap_id);
            return -1;
        }

	ue_context->cell_age = 12; //dummy value
	
	for(i = 0; i < 15; i++)
                imsi[i] = imsi[i] + '0';

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }


        auth_req = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(auth_req);
        pmeta->destination = HSS_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;

        //ipv4->src_addr = IPv4(130,245,144,70);
        //ipv4->dst_addr = IPv4(130,245,144,30);
	memcpy(imsi_p, &imsi[0], 15);

        frame_packet_for_hss(auth_req, &packet[0], enb_ue_s1ap_id, msg_type, slice_id);
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "*************** UE Authentication parameters requesting from HSS ****************\n");
#endif
//        RTE_LOG(INFO, APP, "ip = %o.%o.%o.%o \n", packet[26],packet[27],packet[28],packet[29] );
#ifdef TIME_STATS
        ue_context->time_stamp[INDEX_ATTACH_AUTH_PARAMS_OUT] = rte_rdtsc();//rte_get_tsc_hz();
#endif

        onvm_nflib_return_pkt(auth_req);

	return 0;
}


/*handle received authentication message from hss*/
int
nas_proc_authentication_info_answer(auth_params_type* auth_params, uint32_t enb_ue_s1ap_id){
        ue_context_t * ue_context;

        ue_context = kvs_get(ENB_HTABLE,enb_ue_s1ap_id);
        if(!ue_context) {
            RTE_LOG(ERR, APP, "\nContext not found for enb ID:%x\n",enb_ue_s1ap_id);
            return -1;
        }
	ue_context->conn_state = UE_STATE_ATTACH_AUTH_PARAMS;	
#ifdef TIME_STATS
        ue_context->time_stamp[INDEX_ATTACH_AUTH_PARAMS_IN] = in_time;
#endif
	nas_message_encode(NAS_AUTHENTICATION_REQ, auth_params, enb_ue_s1ap_id);
	return 0;
}

int 
nas_proc_auth_param_res(void){
#ifdef LOGS
    printf("Received auth from HSS\n");
#endif
	return 0;
}



int nas_send_ue_context_release_req(uint32_t enb_ue_s1ap_id){
        struct rte_mbuf* init_context;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = {0x00, 0x09, 0x00, 0x80, 0xbc, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x08, 0x00, 0x04, 0x80, 0x64, 0x6d, 0xbe, 0x00, 0x42, 0x00, 0x0a, 0x18, 0x05, 0xf5, 0xe1, 0x00, 0x60, 0x02, 0xfa, 0xf0, 0x80, 0x00, 0x18, 0x00, 0x6c, 0x00, 0x00, 0x34, 0x00, 0x67, 0x45, 0x00, 0x09, 0x04, 0x0f, 0x80, 0x64, 0x64, 0x0a, 0x39, 0x00, 0x00, 0x00, 0x01, 0x58, 0x27, 0x81, 0x6a, 0x36, 0x9e, 0x01, 0x07, 0x42, 0x02, 0x49, 0x06, 0x20, 0x02, 0xf8, 0x39, 0x00, 0x01, 0x00, 0x38, 0x52, 0x01, 0xc1, 0x01, 0x09, 0x09, 0x03, 0x6f, 0x61, 0x69, 0x04, 0x69, 0x70, 0x76, 0x34, 0x05, 0x01, 0x0a, 0x0a, 0x0a, 0x02, 0x5e, 0x04, 0xfe, 0xfe, 0xde, 0x9e, 0x27, 0x1b, 0x80, 0x80, 0x21, 0x10, 0x03, 0x00, 0x00, 0x10, 0x81, 0x06, 0x08, 0x08, 0x08, 0x08, 0x83, 0x06, 0x08, 0x08, 0x04, 0x04, 0x00, 0x0d, 0x04, 0x08, 0x08, 0x08, 0x08, 0x50, 0x0b, 0xf6, 0x02, 0xf8, 0x39, 0x00, 0x04, 0x01, 0x60, 0x8a, 0xcd, 0x01, 0x00, 0x6b, 0x00, 0x05, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x49, 0x00, 0x20, 0x50, 0x03, 0x72, 0x05, 0xd1, 0x5f, 0x94, 0xb4, 0xb5, 0x13, 0xed, 0xd4, 0x99, 0x1c, 0x50, 0xf0, 0x6e, 0x4d, 0xae, 0xad, 0x1b, 0x73, 0xec, 0x52, 0x87, 0x04, 0xc9, 0xe7, 0x57, 0xda, 0xab, 0xa2};
        uint32_t * enb_ue_s1ap_id_p = (uint32_t *)(&packet[0] + 17);
        ue_context_t * ue_context;
	uint8_t * procedure_code_p = &packet[0] + 1;

	*procedure_code_p = 18; //UE_CONTEXT_RELEASE_REQ
        packet[0] = PACKET_ID_CONTEXT_RELEASE;

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        init_context = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(init_context);
        pmeta->destination = UE_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;

        memcpy(enb_ue_s1ap_id_p, &enb_ue_s1ap_id, sizeof(uint32_t));
#ifdef LOGS
        printf("enb_ue_s1ap_id = %x", enb_ue_s1ap_id);
#endif
        ue_context = kvs_get(ENB_HTABLE, enb_ue_s1ap_id);

        frame_packet(init_context, &packet[0], ue_context);
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "***************  DELETE UE CONTEXT REQUEST sent to UE ****************\n");
#endif
        onvm_nflib_return_pkt(init_context);
        return 0;

}


int nas_send_init_context_setup_req(uint32_t enb_ue_s1ap_id){
	struct rte_mbuf* init_context;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = {0x00, 0x09, 0x00, 0x80, 0xbc, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x08, 0x00, 0x04, 0x80, 0x64, 0x6d, 0xbe, 0x00, 0x42, 0x00, 0x0a, 0x18, 0x05, 0xf5, 0xe1, 0x00, 0x60, 0x02, 0xfa, 0xf0, 0x80, 0x00, 0x18, 0x00, 0x6c, 0x00, 0x00, 0x34, 0x00, 0x67, 0x45, 0x00, 0x09, 0x04, 0x0f, 0x80, 0x64, 0x64, 0x0a, 0x39, 0x00, 0x00, 0x00, 0x01, 0x58, 0x27, 0x81, 0x6a, 0x36, 0x9e, 0x01, 0x07, 0x42, 0x02, 0x49, 0x06, 0x20, 0x02, 0xf8, 0x39, 0x00, 0x01, 0x00, 0x38, 0x52, 0x01, 0xc1, 0x01, 0x09, 0x09, 0x03, 0x6f, 0x61, 0x69, 0x04, 0x69, 0x70, 0x76, 0x34, 0x05, 0x01, 0x0a, 0x0a, 0x0a, 0x02, 0x5e, 0x04, 0xfe, 0xfe, 0xde, 0x9e, 0x27, 0x1b, 0x80, 0x80, 0x21, 0x10, 0x03, 0x00, 0x00, 0x10, 0x81, 0x06, 0x08, 0x08, 0x08, 0x08, 0x83, 0x06, 0x08, 0x08, 0x04, 0x04, 0x00, 0x0d, 0x04, 0x08, 0x08, 0x08, 0x08, 0x50, 0x0b, 0xf6, 0x02, 0xf8, 0x39, 0x00, 0x04, 0x01, 0x60, 0x8a, 0xcd, 0x01, 0x00, 0x6b, 0x00, 0x05, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x49, 0x00, 0x20, 0x50, 0x03, 0x72, 0x05, 0xd1, 0x5f, 0x94, 0xb4, 0xb5, 0x13, 0xed, 0xd4, 0x99, 0x1c, 0x50, 0xf0, 0x6e, 0x4d, 0xae, 0xad, 0x1b, 0x73, 0xec, 0x52, 0x87, 0x04, 0xc9, 0xe7, 0x57, 0xda, 0xab, 0xa2};
        uint32_t * enb_ue_s1ap_id_p = (uint32_t *)(&packet[0] + 17);
        ue_context_t * ue_context;
	uint8_t * procedure_code_p = &packet[0] + 1;

        *procedure_code_p = 9; //UE_INITIAL_CONTEXT_SETUP_REQ


        packet[0] = PACKET_ID_ATTACH_ACCEPT;

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        init_context = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(init_context);
        pmeta->destination = UE_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;

        memcpy(enb_ue_s1ap_id_p, &enb_ue_s1ap_id, sizeof(uint32_t));
#ifdef LOGS
        printf("enb_ue_s1ap_id = %x", enb_ue_s1ap_id);
#endif
        ue_context = kvs_get(ENB_HTABLE, enb_ue_s1ap_id);

        frame_packet(init_context, &packet[0], ue_context);
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "*************** INITIAL CONTEXT SETUP REQUEST sent to UE ****************\n");
#endif
        onvm_nflib_return_pkt(init_context);
        return 0;

}


/*handle messages received from UE here. NAS security setup resp, Auth resp*/
int
nas_proc_ul_transfer_ind(nas_pdu_type * nas_pdu, uint32_t enb_ue_s1ap_id)
{
	
//	nas_message_decrypt();
//	nas_message_decode();
	uint8_t imsi[15];
	ue_context_t * ue_context;

	ue_context = kvs_get(ENB_HTABLE,enb_ue_s1ap_id);
        if(!ue_context) {
	    RTE_LOG(ERR, APP, "\nContext not found for enb ID:%x\n",enb_ue_s1ap_id);
            return -1;
        }

	convert_imsi_to_array(ue_context->imsi, &imsi[0]);

	if(nas_pdu->MM_message_type == AUTHENTICATION_RESPONSE)
	{
#ifdef TIME_STATS
        	ue_context->time_stamp[INDEX_ATTACH_AUTH_RSP_IN] = in_time;
#endif		
		nas_message_encode(NAS_SECURITY_REQ, NULL, enb_ue_s1ap_id);
	}
	else if(nas_pdu->MM_message_type == SECURITY_MODE_COMPLETE)
	{
#ifdef LOGS
	        RTE_LOG(INFO, APP, "\n\n\n");
	        RTE_LOG(INFO, APP, "*************** NAS security response received from UE ****************\n");	
#endif
		if(ue_context->conn_state == UE_STATE_ATTACH_NAS_SECURITY_REQ)
		{
#ifdef TIME_STATS
		        ue_context->time_stamp[INDEX_ATTACH_NAS_SECURITY_RSP_IN] = in_time;
#endif
			nas_send_location_update(&imsi[0], enb_ue_s1ap_id, 
                                                 ue_context->slice_id);
			//nas_send_mmeinfo_req(&imsi[0], enb_ue_s1ap_id);
			//if PDN_CONNECTIVITY_REQ/NAS Security Setup response
			//nas_itti_pdn_connectivity_req(&imsi[0], enb_ue_s1ap_id);
		}
		else if (ue_context->conn_state == UE_STATE_SERVICE_NAS_SECURITY_REQ)
		{
			nas_send_init_context_setup_req(enb_ue_s1ap_id);
		}
	}
	return 0;
}

int
nas_itti_auth_info_req(void){
	//send auth request to hss from here
	return 0;
}


int nas_send_location_update(uint8_t * imsi, uint32_t enb_ue_s1ap_id,
                             uint8_t slice_id)
{
        struct rte_mbuf* auth_req;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = {0x01, 0x00, 0x01, 0x18, 0xc0, 0x00, 0x01, 0x3c, 0x01, 0x00, 0x00, 0x23, 0x23, 0x2e, 0xcf, 0xd6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x40, 0x00, 0x00, 0x38, 0x76, 0x61, 0x73, 0x75, 0x64, 0x65, 0x76, 0x61, 0x6e, 0x65, 0x70, 0x63, 0x32, 0x2e, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x3b, 0x31, 0x34, 0x39, 0x30, 0x36, 0x37, 0x37, 0x37, 0x37, 0x35, 0x3b, 0x32, 0x3b, 0x61, 0x70, 0x70, 0x73, 0x36, 0x61, 0x00, 0x00, 0x01, 0x15, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x24, 0x76, 0x61, 0x73, 0x75, 0x64, 0x65, 0x76, 0x61, 0x6e, 0x65, 0x70, 0x63, 0x32, 0x2e, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x28, 0x00, 0x16, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x00, 0x00, 0x00, 0x00, 0x01, 0x25, 0x40, 0x00, 0x00, 0x24, 0x76, 0x61, 0x73, 0x75, 0x64, 0x65, 0x76, 0x61, 0x6e, 0x65, 0x70, 0x63, 0x32, 0x2e, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x1b, 0x40, 0x00, 0x00, 0x16, 0x73, 0x74, 0x6f, 0x6e, 0x79, 0x62, 0x72, 0x6f, 0x6f, 0x6b, 0x2e, 0x65, 0x64, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x17, 0x32, 0x30, 0x38, 0x39, 0x33, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x00, 0x00, 0x00, 0x05, 0x7f, 0xc0, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x03, 0xec, 0x00, 0x00, 0x05, 0x7d, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x22};
        //struct ipv4_hdr* ipv4 = (struct ipv4_hdr*)(&packet[0] + sizeof(struct ether_hdr));
        int i;
        uint8_t * imsi_p =&packet[0] + 216;

#ifdef TIME_STATS
        ue_context_t * ue_context;

        ue_context = kvs_get(ENB_HTABLE,enb_ue_s1ap_id);
        if(!ue_context) {
            RTE_LOG(ERR, APP, "\nContext not found for enb ID:%x\n",enb_ue_s1ap_id);
            return -1;
        }
#endif

        for(i = 0; i < 15; i++)
                imsi[i] = imsi[i] + '0';

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }


        auth_req = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(auth_req);
        pmeta->destination = HSS_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;
        memcpy(imsi_p, &imsi[0], 15);

        frame_packet_for_hss(auth_req, &packet[0], enb_ue_s1ap_id, PKT_TYPE_ATTACH, slice_id);
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "*************** LOCATION UPDATE REQUEST sent to HSS ****************\n");
#endif
//        RTE_LOG(INFO, APP, "ip = %o.%o.%o.%o \n", packet[26],packet[27],packet[28],packet[29] );

#ifdef TIME_STATS
        ue_context->time_stamp[INDEX_ATTACH_LOCATION_UPDATE_REQ_OUT] = rte_rdtsc();//rte_get_tsc_hz();
#endif
        onvm_nflib_return_pkt(auth_req);
        return 0;
}


int 
nas_proc_pdn_connectivity_res(void){
	return 0;
}


int
nas_send_detatch_accpet(uint32_t enb_ue_s1ap_id)
{
        struct rte_mbuf* seq_command;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = { 0x02, 0x0b, 0x00, 0x23, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x08, 0x00, 0x04, 0x80, 0x64, 0x6d, 0xbe, 0x00, 0x1a, 0x00, 0x0e, 0x0d, 0x37, 0x5f, 0x28, 0x8b, 0x28, 0x00, 0x07, 0x5d, 0x02, 0x00, 0x02, 0x80, 0x20, 0x00};
//      uint32_t enb_ue_s1ap_id;
        uint32_t * enb_ue_s1ap_id_p = (uint32_t *)(&packet[0] + 17);
        ue_context_t * ue_context;

        //memcpy(&enb_ue_s1ap_id, rte_pktmbuf_mtod(pkt, uint8_t*), sizeof(uint32_t));

        packet[0] = PACKET_ID_DETATCH_ACCEPT;

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        seq_command = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(seq_command);
        pmeta->destination = UE_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;

        memcpy(enb_ue_s1ap_id_p, &enb_ue_s1ap_id, sizeof(uint32_t));
#ifdef LOGS
        printf("enb_ue_s1ap_id = %x", enb_ue_s1ap_id);
#endif
        ue_context = kvs_get(ENB_HTABLE, enb_ue_s1ap_id);

        frame_packet(seq_command, &packet[0], ue_context);
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "*************** DETATCH ACCEPT sent to UE ****************\n");
#endif

#ifdef TIME_STATS
        ue_context->time_stamp[INDEX_ATTACH_ACCEPT_OUT] = rte_rdtsc();//rte_get_tsc_hz();
#endif
        onvm_nflib_return_pkt(seq_command);
        return 0;
}


int
start_state_migration(uint32_t enb_ue_s1ap_id)
{
        struct rte_mbuf* seq_command;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
      //  uint8_t packet[] = { 0x01, 0x01, 0x01, 0x01};
//      uint32_t enb_ue_s1ap_id;
        uint32_t * enb_ue_s1ap_id_p;// = (uint32_t *)(&packet[0]);
//	uint32_t * key;
        //memcpy(&enb_ue_s1ap_id, rte_pktmbuf_mtod(pkt, uint8_t*), sizeof(uint32_t));


        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        seq_command = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(seq_command);
        pmeta->destination = 4;
        pmeta->action = ONVM_NF_ACTION_TONF;

  //      memcpy(enb_ue_s1ap_id_p, &enb_ue_s1ap_id, sizeof(uint32_t));
//#ifdef LOGS
//        printf("enb_ue_s1ap_id = %x  %x\n", enb_ue_s1ap_id, *enb_ue_s1ap_id_p);
//#endif

	enb_ue_s1ap_id_p = (uint32_t*)rte_pktmbuf_append(seq_command, sizeof(uint32_t));
	memcpy(enb_ue_s1ap_id_p, &enb_ue_s1ap_id, (TXONLY_DEF_PACKET_LEN - 4));
        onvm_nflib_return_pkt(seq_command);
        return 0;
}

/*send attach accept here*/
/*send attach accept here*/
int 
nas_itti_establish_cnf(uint32_t enb_ue_s1ap_id)
{
        struct rte_mbuf* seq_command;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = { 0x02, 0x0b, 0x00, 0x23, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x08, 0x00, 0x04, 0x80, 0x64, 0x6d, 0xbe, 0x00, 0x1a, 0x00, 0x0e, 0x0d, 0x37, 0x5f, 0x28, 0x8b, 0x28, 0x00, 0x07, 0x5d, 0x02, 0x00, 0x02, 0x80, 0x20, 0x00};
//	uint32_t enb_ue_s1ap_id;
	uint32_t * enb_ue_s1ap_id_p = (uint32_t *)(&packet[0] + 17);
        ue_context_t * ue_context;

        //memcpy(&enb_ue_s1ap_id, rte_pktmbuf_mtod(pkt, uint8_t*), sizeof(uint32_t));

        packet[0] = PACKET_ID_ATTACH_ACCEPT;

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        seq_command = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(seq_command);
        pmeta->destination = UE_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;

	memcpy(enb_ue_s1ap_id_p, &enb_ue_s1ap_id, sizeof(uint32_t));
#ifdef LOGS
	printf("enb_ue_s1ap_id = %x", enb_ue_s1ap_id);
#endif
        ue_context = kvs_get(ENB_HTABLE, enb_ue_s1ap_id);

	frame_packet(seq_command, &packet[0], ue_context);
#ifdef LOGS
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "*************** ATTACH ACCEPT sent to UE ****************\n");
#endif

#ifdef TIME_STATS
        ue_context->time_stamp[INDEX_ATTACH_ACCEPT_OUT] = rte_rdtsc();//rte_get_tsc_hz();
#endif
        onvm_nflib_return_pkt(seq_command);
        return 0;
}
/*send attach accept here*/
int 
nas_itti_establish_cnf_debug(struct rte_mbuf* pkt, uint32_t enb_ue_s1ap_id)
{
        struct rte_mbuf* seq_command;
        struct onvm_pkt_meta* pmeta;
        struct rte_mempool *pktmbuf_pool;
        uint8_t packet[] = { 0x02, 0x0b, 0x00, 0x23, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x08, 0x00, 0x04, 0x80, 0x64, 0x6d, 0xbe, 0x00, 0x1a, 0x00, 0x0e, 0x0d, 0x37, 0x5f, 0x28, 0x8b, 0x28, 0x00, 0x07, 0x5d, 0x02, 0x00, 0x02, 0x80, 0x20, 0x00};
//	uint32_t enb_ue_s1ap_id;
	uint32_t * enb_ue_s1ap_id_p = (uint32_t *)(&packet[0] + 17);
        ue_context_t * ue_context;
#if 0
	ip_options_type * ip_opt;

	ip_opt= mme_pkt_ipopt_hdr(pkt);
        if(ip_opt == NULL)
                RTE_LOG(INFO, APP, "ERROR: enb_ue_s1ap_id not present");
        else
                memcpy(&enb_ue_s1ap_id, enb_ue_s1ap_id_p, sizeof(uint32_t));
#endif

        if(pkt == NULL)
                RTE_LOG(INFO, APP, "something");

        //memcpy(&enb_ue_s1ap_id, rte_pktmbuf_mtod(pkt, uint8_t*), sizeof(uint32_t));

        packet[0] = PACKET_ID_ATTACH_ACCEPT;

        pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if(pktmbuf_pool == NULL) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        seq_command = rte_pktmbuf_alloc(pktmbuf_pool);
        pmeta = onvm_get_pkt_meta(seq_command);
        pmeta->destination = UE_PORT;
        pmeta->action = ONVM_NF_ACTION_OUT;

	memcpy(enb_ue_s1ap_id_p, &enb_ue_s1ap_id, sizeof(uint32_t));

	printf("enb_ue_s1ap_id = %x", enb_ue_s1ap_id);
        ue_context = kvs_get(ENB_HTABLE, enb_ue_s1ap_id);

	frame_packet(seq_command, &packet[0], ue_context);
        RTE_LOG(INFO, APP, "\n\n\n");
        RTE_LOG(INFO, APP, "*************** ATTACH ACCEPT sent to UE ****************\n");
        onvm_nflib_return_pkt(seq_command);
        return 0;
}

