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

#include "lb.h"

#define NAS               26
#define ENB_UE_S1AP_ID 	8
#define S_TMSI		96



uint64_t get_imsi(s1ap_packet_type* s1ap_packet){
        int i = 0;
        uint64_t imsi = 0;
        while(i < 20){
                switch(s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].id){
                        case NAS:
                                if(s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message_type == 0x41){
//                                      && s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.nas_pdu.MM_message.attach_req.EPS_id.id_type == 1){
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
s1ap_packet_parser(struct rte_mbuf* pkt, s1ap_packet_type* s1ap_packet) 
{

        uint8_t* s1ap_pkt_data;
        uint8_t* initial_message;
        uint8_t* cur_pdu;
        uint8_t* nas_pdu_buf;
        uint8_t  ip_options_length = 0;
        struct ipv4_hdr *ip;
#ifdef LOGS
        int procedure_code;
#endif
        int i;

//	s1ap_packet = (s1ap_packet_type*) malloc(sizeof(s1ap_packet_type));
        //TODO:define SCTP header
//        s1ap_pkt_data =  rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + 28;//sizeof(struct sctp_hdr);
	ip = onvm_pkt_ipv4_hdr(pkt);
        if((ip->version_ihl&0x0f) > 5)
                ip_options_length = ((ip->version_ihl&0x0f) - 5) * 32;
        
        s1ap_pkt_data =  rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(pkt_identifier_t) + sizeof(struct udphdr);
#ifdef LOGS
	procedure_code = *(s1ap_pkt_data + 1);
#endif
        if(s1ap_pkt_data == NULL)
                return -1;
        s1ap_packet->message_type = *(s1ap_pkt_data);
        //RTE_LOG(INFO, APP, "s1ap message type = 0x%x \n", s1ap_msg_type);
        s1ap_packet->message.ue_init_msg.procedure_code = *(s1ap_pkt_data + 1);
        s1ap_packet->message.ue_init_msg.criticality = *(s1ap_pkt_data + 2);
        s1ap_packet->message.ue_init_msg.size = *(s1ap_pkt_data + 3);
        //RTE_LOG(INFO, APP, "procedure_code = %d \n", procedure_code);
#ifdef LOGS
        RTE_LOG(INFO, APP, "procedure_code = %d %s:%d\n",procedure_code,__func__,__LINE__);
#endif
        if(1)//s1ap_packet->message_type == 0)// && s1ap_packet->message.ue_init_msg.procedure_code == 12)
        {
                initial_message = s1ap_pkt_data + 4;
                s1ap_packet->message.ue_init_msg.value.init_msg.message_type = *initial_message;
                //RTE_LOG(INFO, APP, "initial_message = %d \n", *initial_message);
                if(1)//s1ap_packet->message.ue_init_msg.value.init_msg.message_type == 0)
                {
                        s1ap_packet->message.ue_init_msg.value.init_msg.protocolIEs = *(initial_message+1) << 8;
                        s1ap_packet->message.ue_init_msg.value.init_msg.protocolIEs = s1ap_packet->message.ue_init_msg.value.init_msg.protocolIEs + *(initial_message+2);
                        cur_pdu = initial_message + 3;
#ifdef LOGS
                        RTE_LOG(INFO, APP, "protocol_IE_no = 0x%x \n", s1ap_packet->message.ue_init_msg.value.init_msg.protocolIEs);
#endif
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
#ifdef LOGS
                                            		RTE_LOG(INFO, APP, "Attach complete received!!! \n");
#endif
						}
						break;

					case ENB_UE_S1AP_ID:
						memcpy(&s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.enb_ue_s1ap_id.id, cur_pdu, s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].size);
#ifdef LOGS
						RTE_LOG(INFO, APP, "eNB_UE_S1ap_id = 0x%x \n", s1ap_packet->message.ue_init_msg.value.init_msg.pdus[i].pdu.enb_ue_s1ap_id.id);
#endif
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
