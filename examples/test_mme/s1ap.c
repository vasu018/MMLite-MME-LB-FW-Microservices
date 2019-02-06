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
#include <netinet/in.h>
#include <netinet/udp.h>

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


uint32_t get_imsi32(uint64_t imsi)
{
	uint32_t imsi32;
	memcpy(&imsi32, (uint32_t*)(&imsi)+1, sizeof(uint32_t));
	return imsi32;
}

int
s1ap_packet_parser(struct rte_mbuf* pkt, s1ap_packet_type* s1ap_packet) 
{

        uint8_t* s1ap_pkt_data;
        uint8_t* initial_message;
        uint8_t* cur_pdu;
        uint8_t* nas_pdu_buf;
        uint8_t  ip_options_length = 0;
        struct ipv4_hdr *ip;
        int procedure_code;
        int i;

//	s1ap_packet = (s1ap_packet_type*) malloc(sizeof(s1ap_packet_type));
        //TODO:define SCTP header
//        s1ap_pkt_data =  rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 28;//sizeof(struct sctp_hdr);
	ip = onvm_pkt_ipv4_hdr(pkt);
        if((ip->version_ihl&0x0f) > 5)
                ip_options_length = ((ip->version_ihl&0x0f) - 5) * 32;
        
        s1ap_pkt_data =  rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(pkt_identifier_t) + sizeof(struct udphdr);
	procedure_code = *(s1ap_pkt_data + 1);
        if(s1ap_pkt_data == NULL)
                return -1;
        s1ap_packet->message_type = *(s1ap_pkt_data);
        //RTE_LOG(INFO, APP, "s1ap message type = 0x%x \n", s1ap_msg_type);
        s1ap_packet->message.ue_init_msg.procedure_code = *(s1ap_pkt_data + 1);
        s1ap_packet->message.ue_init_msg.criticality = *(s1ap_pkt_data + 2);
        s1ap_packet->message.ue_init_msg.size = *(s1ap_pkt_data + 3);
        //RTE_LOG(INFO, APP, "procedure_code = %d \n", procedure_code);
        RTE_LOG(INFO, APP, "procedure_code = %d %s:%d\n",procedure_code,__func__,__LINE__);
        if(s1ap_packet->message_type == 0)// && s1ap_packet->message.ue_init_msg.procedure_code == 12)
        {
                initial_message = s1ap_pkt_data + 4;
                s1ap_packet->message.ue_init_msg.value.init_msg.message_type = *initial_message;
                //RTE_LOG(INFO, APP, "initial_message = %d \n", *initial_message);
                if(s1ap_packet->message.ue_init_msg.value.init_msg.message_type == 0)
                {
                        s1ap_packet->message.ue_init_msg.value.init_msg.protocolIEs = *(initial_message+1) << 8;
                        s1ap_packet->message.ue_init_msg.value.init_msg.protocolIEs = s1ap_packet->message.ue_init_msg.value.init_msg.protocolIEs + *(initial_message+2);
                        cur_pdu = initial_message + 3;
                        RTE_LOG(INFO, APP, "protocol_IE_no = 0x%x \n", s1ap_packet->message.ue_init_msg.value.init_msg.protocolIEs);
                        for(i = 0; i < s1ap_packet->message.ue_init_msg.value.init_msg.protocolIEs; i++)
                        {
                                s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].id = *(cur_pdu) << 8;
                                s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].id = s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].id + *(cur_pdu + 1);
                                cur_pdu+=2;
                                s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].criticality = *cur_pdu;
                                cur_pdu++;
                                s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].size = *cur_pdu;
                                cur_pdu++;
                                //RTE_LOG(INFO, APP, "cur_pdu_id = %d \n", cur_pdu_id);
				switch(s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].id){
					case NAS:
//                                if(s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].id == 26)
//                                {
                                        	nas_pdu_buf = cur_pdu + 1;
						nas_message_decode(&s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu, nas_pdu_buf);
/*
						if(s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message_type == 0x41
							&& s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message.attach_req.EPS_id.id_type == 1){
					                nas_proc_establish_ind(&s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message.attach_req.EPS_id.identity[0]);
	                                        } else if(s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message_type == 0x43) {
*/
						if(s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message_type == 0x43) {						
                                            		RTE_LOG(INFO, APP, "Attach complete received!!! \n");
						}
						break;

					case ENB_UE_S1AP_ID:
						memcpy(&s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.enb_ue_s1ap_id.id, cur_pdu, s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].size);
						RTE_LOG(INFO, APP, "eNB_UE_S1ap_id = 0x%x \n", s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.enb_ue_s1ap_id.id);
						break;	
//				for(j = 0; j < 15; j++)
//                                         RTE_LOG(INFO, APP, "IMSI = %x \n", s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message.attach_req.EPS_id.identity[j]);
//                                }

					case S_TMSI:
						memcpy(&s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.s_tmsi.id, cur_pdu, s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].size);
                                }
                                cur_pdu+=s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].size;
                        }
                }
        }


	return 0;
}

int
s1ap_populate_ue_context(ue_context_t * ue_context, void* packet, message_type message){
	int i = 0;
	s1ap_packet_type* s1ap_packet;

	switch(message) {
        case MSG_ATTACH_REQUEST:
            i = 0;
            s1ap_packet = (s1ap_packet_type*)packet;
            while(i < 20){
                switch(s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].id){
                case NAS:
                        memcpy(&ue_context->imsi, 
                               &s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].
                               pdu.nas_pdu.MM_message.attach_req.EPS_id.imsi, sizeof(uint64_t) );

                        printf("Setting hashtable entry with the IMSI value\n");
                        kvs_set(IMSI_HTABLE, get_imsi32(s1ap_packet->message.ue_init_msg.value.
                                                        init_msg.pdus[i].pdu.nas_pdu.MM_message.
                                                        attach_req.EPS_id.imsi), 
                                                        (void *)ue_context);
                        break;
                case ENB_UE_S1AP_ID:
                        memcpy(&ue_context->enb_ue_s1ap_id, &s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.enb_ue_s1ap_id.id, sizeof(uint32_t));
                        printf("Setting hashtable entry with the enb_ue_id  value\n");
                        kvs_set(ENB_HTABLE, s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.enb_ue_s1ap_id.id, (void *)ue_context);
                        break;


                    }

            i++;
            }
            break;
        case MSG_AUTH_RESPONSE:
            break;
        default:
            break;
       }

	return 0;
}


void convert_imsi_to_array(uint64_t imsi, uint8_t* imsi_arr){
	uint8_t* imsi_p = (uint8_t *)&imsi;
	int j = 0;

	for(j = 0; j < 15; j++)
        {
        	if(j % 2 == 0)
                {
                	imsi_arr[j] = (*imsi_p & 0xf0) >> 4;
                        imsi_p++;
                }
                else
                	imsi_arr[j] = (*imsi_p & 0x0f);

        }
}

uint64_t get_imsi(s1ap_packet_type* s1ap_packet){
	int i = 0;
	uint64_t imsi = 0;
	while(i < 20){
                switch(s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].id){
                	case NAS:
				if(s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message_type == 0x41){
//                                	&& s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message.attach_req.EPS_id.id_type == 1){
                        		imsi = s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message.attach_req.EPS_id.imsi;
				}
				break;
			default:
				break;
		}
		i++;
	}
	return imsi;

}



uint8_t get_msg_type(s1ap_packet_type* s1ap_packet){
        int i = 0;
//        uint64_t imsi = 0;
        while(i < 20){
                switch(s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].id){
                        case NAS:
                                return s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message_type;
//                                break;
                        default:
                                break;
                }
                i++;
        }
        return 0;

}


uint32_t get_enb_ue_s1ap_id(s1ap_packet_type* s1ap_packet){
        int i = 0;
        uint32_t enb_ue_s1ap_id = 0;
        while(i < 20){
//		RTE_LOG(INFO, APP, "get_enb_ue_s1ap_id: pdu_id = 0x%x \n", s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].id);
                switch(s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].id){
                case ENB_UE_S1AP_ID:
                    enb_ue_s1ap_id = s1ap_packet->message.ue_init_msg.value.
                        init_msg.pdus[i].pdu.enb_ue_s1ap_id.id;
                    return enb_ue_s1ap_id;
                default:
                    break;
                }
                i++;
        }
	return enb_ue_s1ap_id;

}

int
s1ap_mme_handle_initial_ue_message(struct rte_mbuf* pkt, uint8_t slice_id) 
{
	//      mme_app_handle_initial_ue_message();
	s1ap_packet_type* s1ap_packet;
	ue_context_t * ue_context;
	uint8_t imsi_arr[15];
	struct udp_hdr  *udp = mme_pkt_udp_hdr(pkt);
	struct ipv4_hdr *ip;
        uint8_t     msg_type = 255;

	s1ap_packet = (s1ap_packet_type*) malloc(sizeof(s1ap_packet_type));
	s1ap_packet_parser(pkt, s1ap_packet);
	ue_context = kvs_get(ENB_HTABLE,get_enb_ue_s1ap_id(s1ap_packet));
	if(get_msg_type(s1ap_packet) == SERVICE_REQUEST) {
		RTE_LOG(INFO, APP, "\n\n\n");
                RTE_LOG(INFO, APP, "*************** Received Service Request ****************\n");
		if(ue_context != NULL) {
			RTE_LOG(INFO, APP, "UE Context found for service Request \n");
                        ue_context->conn_state = UE_STATE_SERVICE_REQ;
			ue_context->udp_port = ntohs(udp->src_port);
                        ue_context->slice_id = slice_id;
//			RTE_LOG(INFO, APP, "get_enb_ue_s1ap_id = 0x%x \n", get_enb_ue_s1ap_id(s1ap_packet));
                        msg_type = PKT_TYPE_SERVICE;
		} else {
			RTE_LOG(INFO, APP, "ERROR:  UE Context not found \n");
                        free(s1ap_packet);
			return -1;
		}
	}
	else if(get_msg_type(s1ap_packet) == ATTACH_REQUEST)
        {
		RTE_LOG(INFO, APP, "\n\n\n");
                RTE_LOG(INFO, APP, "*************** Received Attach Request ****************\n");
	        if(kvs_get(IMSI_HTABLE,get_imsi32(get_imsi(s1ap_packet))) == NULL) {
                    //TODO search contxt and context not found
	                RTE_LOG(INFO, APP, "UE Context not found. Creating UE context!!! \n");
	                ue_context = (ue_context_t *) rte_malloc(NULL, sizeof(ue_context_t), 0);
                        ue_context->conn_state = UE_STATE_ATTACH_REQ;
	                s1ap_populate_ue_context(ue_context, s1ap_packet, ATTACH_REQUEST);
                        ue_context->slice_id = slice_id;

                        /*
                         * Get the src ip from the packet to put into ue context
                         */
                        
                        ip = onvm_pkt_ipv4_hdr(pkt);
                        ue_context->src_ip = (ip->src_addr);

	                ue_context->udp_port = ntohs(udp->src_port);
	//              RTE_LOG(INFO, APP, "get_enb_ue_s1ap_id = 0x%x \n", get_enb_ue_s1ap_id(s1ap_packet));
	                kvs_set(IMSI_HTABLE, get_imsi32(get_imsi(s1ap_packet)), (void *)ue_context);
	                kvs_set(ENB_HTABLE, get_enb_ue_s1ap_id(s1ap_packet), (void *)ue_context);
                        msg_type = PKT_TYPE_ATTACH;
#ifdef DEBUG_PACKET_SCALE
                        nas_itti_establish_cnf_debug(pkt, get_enb_ue_s1ap_id(s1ap_packet));
                        RTE_LOG(INFO, APP, "*************** Sending Attach accept ******************\n");
                        return 0;
#endif
	        } else {
			RTE_LOG(INFO, APP, "ERROR:  UE Context found. Already attached UE. Dropping packet \n");
                        free(s1ap_packet);
	                return -1;
		}
	} else {
            free(s1ap_packet);
            return -1;
        }


	convert_imsi_to_array(ue_context->imsi, &imsi_arr[0]);

        /*
         * Set state to UE_STATE_ATTACH_AUTH_PARAMS since we need to send
         * auth params req to HSS now
         */
	nas_proc_establish_ind(&imsi_arr[0], get_enb_ue_s1ap_id(s1ap_packet), 
                               msg_type, slice_id);
	
	free(s1ap_packet);
        return 0;
}

int
s1ap_generate_downlink_nas_transport(void){
	return 0;
}

int
s1ap_mme_handle_uplink_nas_transport(struct rte_mbuf* pkt, uint8_t msg_type, uint8_t slice_id)
{

	int i = 0;
        s1ap_packet_type s1ap_packet;
        if (s1ap_packet_parser(pkt, &s1ap_packet) != 0) {
            printf("\n%s: S1ap packet not formed\n",__func__);
            return -1;
        }

	while(s1ap_packet.message.ue_init_msg.value.init_msg.pdus[i].id != NAS)
		i++;
	//TODO: get imsi from shared mem. mapped to enb-ue-s1ap-id
	if(s1ap_packet.message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message_type != ATTACH_COMPLETE){
		nas_proc_ul_transfer_ind(&s1ap_packet.message.ue_init_msg.
                                         value.init_msg.pdus[i].pdu.nas_pdu, 
                                         get_enb_ue_s1ap_id(&s1ap_packet));
        }

	if(s1ap_packet.message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message_type == ATTACH_COMPLETE){
//                printf("\n%s:%d\n",__func__,get_enb_ue_s1ap_id(&s1ap_packet));
                s11_send_modify_bearer_req(get_enb_ue_s1ap_id(&s1ap_packet), msg_type, slice_id);
        }

	return 0;
}



int
s1ap_handle_initial_context_setup_response(struct rte_mbuf* pkt, uint8_t msg_type, uint8_t slice_id)
{

        s1ap_packet_type s1ap_packet;
//        s1ap_packet = (s1ap_packet_type*) malloc(sizeof(s1ap_packet_type));
        s1ap_packet_parser(pkt, &s1ap_packet);


        s11_send_modify_bearer_req(get_enb_ue_s1ap_id(&s1ap_packet), msg_type, slice_id);
//      free(s1ap_packet);

        return 0;
}



