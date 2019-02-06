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
#include <netinet/in.h>
#include <netinet/udp.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include <rte_ether.h>
#include <rte_ethdev.h>
#include "mme.h"
//#include "s6a.h"

#define NF_TAG "simple_forward"

uint32_t get_data(uint8_t* data_start, int length)
{
	uint32_t data = 0;
	int i = 0;
	for(i = 0; i < length; i++)
		data = data*256 + *(data_start+i);
	return data;
}


int s6a_packet_parser(struct rte_mbuf* pkt, s6a_packet_type* s6a_packet){
	uint8_t * s6a_pkt_data;
	int avp_count = 0;
	uint8_t * cur_avp_segment;
//	uint8_t * auth_info_start;
	uint8_t * eutran_vector_start;
	int i;
	struct ipv4_hdr* ip;
	uint8_t ip_options_length = 0;
	uint8_t * cur_eutran_segment;

//	uint32_t next_segment_code;
	ip = onvm_pkt_ipv4_hdr(pkt);
        if((ip->version_ihl&0x0f) > 5)
                ip_options_length = ((ip->version_ihl&0x0f) - 5) * 32;
	
	s6a_pkt_data = rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + ip_options_length + sizeof(struct udphdr);
	
	s6a_packet->version = *s6a_pkt_data;
	s6a_packet->length = get_data(s6a_pkt_data + 1, 3);
	s6a_packet->flag = *(s6a_pkt_data + 4);
	s6a_packet->command_code = get_data(s6a_pkt_data + 5, 3);
	s6a_packet->application_id = get_data(s6a_pkt_data + 8, 4);
	s6a_packet->hop_by_hop_id = get_data(s6a_pkt_data + 12, 4);
	s6a_packet->end_to_end_id = get_data(s6a_pkt_data + 16, 4);
	cur_avp_segment = s6a_pkt_data + 20;
	while(avp_count < MAX_AVP){
		s6a_packet->avps[avp_count].avp_code = get_data(cur_avp_segment, 4);
		s6a_packet->avps[avp_count].avp_flags = *(cur_avp_segment+4);
		s6a_packet->avps[avp_count].length = get_data(cur_avp_segment + 5, 3);
//		s6a_packet->avps[avp_count].vendor_id = get_data(cur_avp_segment + 8, 4);
		switch(s6a_packet->avps[avp_count].avp_code){

		case 1413://auth info
			eutran_vector_start = cur_avp_segment + 12;
			s6a_packet->avps[avp_count].vendor_id = get_data(cur_avp_segment + 8, 4);
                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.code = get_data(eutran_vector_start, 4);
        	        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.flags = *(eutran_vector_start+4);
	                s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.length = get_data(eutran_vector_start + 5, 3);
			s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.vendor_id = get_data(eutran_vector_start + 8, 4);
			cur_eutran_segment = eutran_vector_start + 12;
			for(i = 0; i < 4; i++){
				switch(get_data(cur_eutran_segment, 4)){
				
				case 1447:
					s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.rand_avp.code = get_data(cur_eutran_segment, 4);
                		        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.rand_avp.flags = *(cur_eutran_segment+4);
        	                	s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.rand_avp.length = get_data(cur_eutran_segment + 5, 3);
		                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.rand_avp.vendor_id = get_data(cur_eutran_segment + 8, 4); 
					memcpy(&(s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.rand_avp.rand[0]), cur_eutran_segment+12, RAND_LEN);

					cur_eutran_segment += s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.rand_avp.length;	
					break;		

				case 1448:
                                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.xres_avp.code = get_data(cur_eutran_segment, 4);
                                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.xres_avp.flags = *(cur_eutran_segment+4);
                                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.xres_avp.length = get_data(cur_eutran_segment + 5, 3);
                                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.xres_avp.vendor_id = get_data(cur_eutran_segment + 8, 4);
                                        memcpy(&(s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.xres_avp.xres[0]), cur_eutran_segment+12, XRES_LEN);

                                        cur_eutran_segment += s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.xres_avp.length;
                                        break;
			
                                case 1449:
                                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.autn_avp.code = get_data(cur_eutran_segment, 4);
                                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.autn_avp.flags = *(cur_eutran_segment+4);
                                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.autn_avp.length = get_data(cur_eutran_segment + 5, 3);
                                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.autn_avp.vendor_id = get_data(cur_eutran_segment + 8, 4);
                                        memcpy(&(s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.autn_avp.autn[0]), cur_eutran_segment+12, AUTN_LEN);

                                        cur_eutran_segment += s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.autn_avp.length;
                                        break;

                                case 1450:
                                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.kasme_avp.code = get_data(cur_eutran_segment, 4);
                                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.kasme_avp.flags = *(cur_eutran_segment+4);
                                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.kasme_avp.length = get_data(cur_eutran_segment + 5, 3);
                                        s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.kasme_avp.vendor_id = get_data(cur_eutran_segment + 8, 4);
                                        memcpy(&(s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.kasme_avp.kasme[0]), cur_eutran_segment+12, KASME_LEN);

                                        cur_eutran_segment += s6a_packet->avps[avp_count].s6a_avp.auth_info.eutran_vector.kasme_avp.length;
                                        break;
				}
				
			}
			break;
		case 1400: // subscriptio data
			break;
		case 268://result
			break;
		
		}
		cur_avp_segment += s6a_packet->avps[avp_count].length;
		avp_count++;
		if(s6a_packet->avps[avp_count].avp_code == 268)
			break;

	}

	return 0;

}


uint8_t * get_randp(s6a_packet_type * s6a_packet)
{
        int i = 0;
        while(i < MAX_AVP){
                switch(s6a_packet->avps[i].avp_code){
                case 1413:
                        return &s6a_packet->avps[i].s6a_avp.auth_info.eutran_vector.rand_avp.rand[0];
                        break;
                default:
                        break;
                }
                i++;
        }	
	return NULL;
}


uint8_t * get_autnp(s6a_packet_type * s6a_packet)
{
        int i = 0;
        while(i < MAX_AVP){
                switch(s6a_packet->avps[i].avp_code){
                        case 1413:
                                return &s6a_packet->avps[i].s6a_avp.auth_info.eutran_vector.autn_avp.autn[0];
                                break;
                        default:
                                break;
                }
                i++;
        }
	return NULL;
}


int
s6a_generate_authentication_info_req(struct rte_mbuf* pkt){
	auth_params_type auth_params;
	uint32_t enb_ue_s1ap_id;
	s6a_packet_type s6a_packet;
	ip_options_type* ip_opt;
        uint8_t    *randp, *autnp;
//	memcpy(&enb_ue_s1ap_id, rte_pktmbuf_mtod(pkt, uint8_t*), sizeof(uint32_t));
//	printf("\nenb_ue_s1ap_id = 0x%x \n", enb_ue_s1ap_id);
	//TODO get enb_ue_s1ap_id from ue_contex

	s6a_packet_parser(pkt,  &s6a_packet);
	ip_opt= mme_pkt_ipopt_hdr(pkt);	
	if(ip_opt == NULL)
		RTE_LOG(INFO, APP, "ERROR: enb_ue_s1ap_id not present");
	else
		memcpy(&enb_ue_s1ap_id, &ip_opt->ip_options[0], sizeof(uint32_t));
        
        randp = get_randp(&s6a_packet);
        if (randp)
            memcpy(&auth_params.rand, &randp, 16);

        autnp = get_autnp(&s6a_packet);
        if (autnp)
            memcpy(&auth_params.autn, &autnp, 16);

	nas_proc_authentication_info_answer(&auth_params, enb_ue_s1ap_id);	
//	memcpy(&query_reply.ak[0], rte_pktmbuf_mtod(pkt, uint8_t*), 6);
//	memcpy(&query_reply.ak[0], rte_pktmbuf_mtod(pkt, uint8_t*), 6);
        
        
	return 0;
}
