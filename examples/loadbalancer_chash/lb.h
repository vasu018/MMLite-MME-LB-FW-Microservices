#ifndef LB_H
#define LB_H

# define ATTACH_REQUEST                                       0b01000001 /* 65 = 0x41 */
# define DETACH_REQUEST                                       0b01000101 /* 69 = 0x45 */
# define SERVICE_REQUEST                                      0b01001101 /* TODO: TBD - 77 = 0x4d */


typedef struct pkt_identifier_s {
        uint8_t slice_id;
        uint8_t msg_type;
		uint8_t MMEID;
}pkt_identifier_t;

typedef struct{
        uint8_t length;
        uint8_t* UE_capabilities;
}UE_capability_type;

typedef struct{
        uint8_t length;
        uint8_t odd_even;
        uint8_t id_type;
        uint8_t identity[16];
	uint64_t imsi;
        uint8_t test;
}mobile_identity_type;

typedef struct{
        uint8_t message_type;
        uint8_t security_context;
        uint8_t NAS_key_set_id;
        uint8_t attach_type;
        mobile_identity_type EPS_id;
        UE_capability_type network_capability;
        uint8_t* ESM_msg;  // create proper struct
}MM_msg_type;


typedef struct{
        uint8_t security_context;
        uint8_t NAS_key_set_id;
        uint8_t attach_type;
        mobile_identity_type EPS_id;
        UE_capability_type network_capability;
        uint8_t* ESM_msg;
}attach_req_type;


typedef struct{
	uint8_t length;
	uint8_t auth_resp[8];
}auth_response_type;

typedef struct{
        uint8_t security_header_type;
        uint8_t protocol_discriminator;
        uint8_t MM_message_type;
	union {
		attach_req_type attach_req;
		auth_response_type auth_resp;
	}MM_message;
}nas_pdu_type;

typedef struct{
	uint32_t id;
}enb_ue_s1ap_id_type;

typedef struct{
        uint32_t id;
}s_tmsi_type;

typedef struct {
        uint16_t id;
        uint8_t criticality;
        uint8_t size;
        union {
                nas_pdu_type nas_pdu;
		enb_ue_s1ap_id_type enb_ue_s1ap_id;
		s_tmsi_type s_tmsi;
        }pdu;
}protocol_pdu;


typedef struct {
        uint8_t message_type;
        short protocolIEs;
        protocol_pdu  pdus[20];

}initial_message_type;



typedef struct {
        uint8_t procedure_code;
        uint8_t criticality;
        uint8_t size;
        union  {
                initial_message_type init_msg;
        }value;
}initiating_msg_type;

typedef struct {
        uint8_t message_type;
        union{
                initiating_msg_type ue_init_msg;
        }message;
}s1ap_packet_type;

#endif

uint8_t get_msg_type(s1ap_packet_type* s1ap_packet);
uint64_t get_imsi(s1ap_packet_type* s1ap_packet);
int s1ap_packet_parser(struct rte_mbuf* pkt, s1ap_packet_type* s1ap_packet);
int nas_message_decode(nas_pdu_type* nas_pdu, uint8_t * nas_pdu_buf);
int cmp_enb_ue_s1ap_id (const void * a, const void * b);
void add_connection(int slice_id,uint64_t imsi,int host_id);
int get_connection(int slice_id,uint64_t imsi);
uint32_t get_enb_ue_s1ap_id(s1ap_packet_type* s1ap_packet);
int init_ring_chash(void);
