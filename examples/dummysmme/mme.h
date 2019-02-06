#include "ue_context.h"
#include "s6a.h"
//#include "kvs_main.h"
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>

#define LOGS	
#define TIME_STATS

#define IDMMEIDENTITY 7
#define TXONLY_DEF_PACKET_LEN 64

//#define DEBUG_PACKET_SCALE

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_HDRLEN_HSS  0x06
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define IP_VHL_DEF_HSS (IP_VERSION | IP_HDRLEN_HSS)
//TODO: remove this. get imsi from shared mem. mapped to enb-ue-s1ap-id
#define ENB_UE_S1AP_ID 	8
#define NAS 		26
#define S_TMSI		96

#define S1AP_PORT	2343		
#define S6A_PORT	2345
#define S11_PORT	2347
#define EXP_START_PORT	2355
#define EXP_STOP_PORT	2356

#define  S6A_AUTH_INFO 		318
#define  S6A_LAU		316


#define S11_CREATE_SESSION_REQ          0x20
#define S11_MODIFY_BEARER_REQ           0x22
#define S11_CREATE_SESSION_RSP          0x21
#define S11_MODIFY_BEARER_RSP           0x23


#define MME_LOC_UPDATE_GET_PDN              0x01
#define MME_LOC_UPDATE_USR_UPDATE_RAND_SQN  0x02
#define MME_LOC_UPDATE_USR_UPDATE_SQN       0x03
#define MME_LOC_UPDATE_GET_USR_DATA         0x04
#define MME_LOC_UPDATE_GET_MMEID            0x05
#define MME_AUTH_REQ                        0x06


#define PACKET_ID_NAS_SEC_REQ       0x02
#define PACKET_ID_AUTH_REQ          0x03
#define PACKET_ID_ATTACH_ACCEPT     0x04

# define ATTACH_REQUEST                                       0b01000001 /* 65 = 0x41 */
# define ATTACH_ACCEPT                                        0b01000010 /* 66 = 0x42 */
# define ATTACH_COMPLETE                                      0b01000011 /* 67 = 0x43 */
# define ATTACH_REJECT                                        0b01000100 /* 68 = 0x44 */
# define DETACH_REQUEST                                       0b01000101 /* 69 = 0x45 */
# define DETACH_ACCEPT                                        0b01000110 /* 70 = 0x46 */
# define TRACKING_AREA_UPDATE_REQUEST                         0b01001000 /* 72 = 0x48 */
# define TRACKING_AREA_UPDATE_ACCEPT                          0b01001001 /* 73 = 0x49 */
# define TRACKING_AREA_UPDATE_COMPLETE                        0b01001010 /* 74 = 0x4a */
# define TRACKING_AREA_UPDATE_REJECT                          0b01001011 /* 75 = 0x4b */
# define EXTENDED_SERVICE_REQUEST                             0b01001100 /* 76 = 0x4c */
# define SERVICE_REQUEST   			              0b01001101 /* TODO: TBD - 77 = 0x4d */
# define SERVICE_REJECT                                       0b01001110 /* 78 = 0x4e */
# define GUTI_REALLOCATION_COMMAND                            0b01010000 /* 80 = 0x50 */
# define GUTI_REALLOCATION_COMPLETE                           0b01010001 /* 81 = 0x51 */
# define AUTHENTICATION_REQUEST                               0b01010010 /* 82 = 0x52 */
# define AUTHENTICATION_RESPONSE                              0b01010011 /* 83 = 0x53 */
# define AUTHENTICATION_REJECT                                0b01010100 /* 84 = 0x54 */
# define AUTHENTICATION_FAILURE                               0b01011100 /* 92 = 0x5c */
# define IDENTITY_REQUEST                                     0b01010101 /* 85 = 0x55 */
# define IDENTITY_RESPONSE                                    0b01010110 /* 86 = 0x56 */
# define SECURITY_MODE_COMMAND                                0b01011101 /* 93 = 0x5d */
# define SECURITY_MODE_COMPLETE                               0b01011110 /* 94 = 0x5e */
# define SECURITY_MODE_REJECT                                 0b01011111 /* 95 = 0x5f */
# define EMM_STATUS                                           0b01100000 /* 96 = 0x60 */
# define EMM_INFORMATION                                      0b01100001 /* 97 = 0x61 */
# define DOWNLINK_NAS_TRANSPORT                               0b01100010 /* 98 = 0x62 */
# define UPLINK_NAS_TRANSPORT                                 0b01100011 /* 99 = 0x63 */
# define CS_SERVICE_NOTIFICATION                              0b01100100 /* 100 = 0x64 */
# define DOWNLINK_GENERIC_NAS_TRANSPORT                       0b01101000 /* 104 = 0x68 */
# define UPLINK_GENERIC_NAS_TRANSPORT                         0b01101001 /* 101 = 0x69 */





extern char IMSI_HTABLE[];
extern char S11_HTABLE[]; 
extern char MME_HTABLE[];
extern char ENB_HTABLE[];
extern char GUTI_HTABLE[];

uint8_t imsi_g[15];
double in_time;
//uint64_t out_time;



typedef struct pkt_identifier_s {
        uint8_t slice_id;
        uint8_t msg_type;
}pkt_identifier_t;

typedef struct {
	uint8_t ip_options[32];
}ip_options_type;

typedef enum {	
	MESSAGE_MIN = 0x00,
	MSG_ATTACH_REQUEST, 
	MSG_AUTH_RESPONSE, 
	MESSAGE_MAX = 0x10
}message_type;


typedef enum {	
	PKT_TYPE_ATTACH=0,
	PKT_TYPE_SERVICE,
        PKT_TYPE_DETACH
}pkt_type;


typedef struct{
        uint8_t rand[16];
        uint8_t autn[16];
}auth_params_type;


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

typedef enum {
	NAS_SECURITY_REQ, 
	NAS_AUTHENTICATION_REQ
	} message_id_type;

typedef struct pkt_data_s{
    TAILQ_ENTRY(pkt_data_s) tailq;
    struct rte_mbuf* pkt;
    struct onvm_pkt_meta* meta;
} pkt_data_t;


int hex_to_num(char *hex, uint8_t *num_array);

uint32_t get_imsi32(uint64_t imsi);

struct udp_hdr*
mme_pkt_udp_hdr(struct rte_mbuf* pkt);

ip_options_type*
mme_pkt_ipopt_hdr(struct rte_mbuf* pkt);

void frame_packet_for_sgw(struct rte_mbuf *packet, uint8_t * payload, uint32_t enb_ue_s1ap_id,
                          uint8_t msg_type, uint8_t slice_id);

void frame_packet_for_hss(struct rte_mbuf *packet, uint8_t * payload, 
                          uint32_t enb_ue_s1ap_id, uint8_t msg_type, uint8_t slice_id);

void frame_packet_debug(struct rte_mbuf *packet, uint8_t *payload, uint32_t udp_dest);
void frame_packet(struct rte_mbuf *packet, uint8_t *payload, ue_context_t *ue_context); 

int nas_message_decode(nas_pdu_type* nas_pdu, uint8_t * nas_pdu_buf);
/*create message to UE here :  NAS security setup request, Auth request*/

//int nas_encode_auth_req(uint8_t* rand, uint8_t* sqn, uint8_t* ak, uint32_t enb_ue_s1ap_id);
int nas_encode_auth_req(uint8_t* rand, uint8_t* autn, uint32_t enb_ue_s1ap_id);

int nas_encode_security_command(uint32_t enb_ue_s1ap_id);


int
nas_message_encode(message_id_type msg_id, void * message, uint32_t enb_ue_s1ap_id);



/*initial UE message is handled here. called from s1ap*/
int
nas_proc_establish_ind(uint8_t * imsi, uint32_t enb_ue_s1ap_id, 
                       uint8_t msg_type, uint8_t slice_id);


/*handle received authentication message from hss*/
int
nas_proc_authentication_info_answer(auth_params_type* auth_params, uint32_t enb_ue_s1ap_id);


int
nas_proc_auth_param_res(void);

/*handle messages received from UE here. NAS security setup resp, Auth resp*/
int
nas_proc_ul_transfer_ind(nas_pdu_type * nas_pdu, uint32_t enb_ue_s1ap_id);

int
nas_itti_auth_info_req(void);

int nas_itti_pdn_connectivity_req(uint8_t * imsi, uint32_t enb_ue_s1ap_id);

int nas_send_location_update(uint8_t * imsi, uint32_t enb_ue_s1ap_id, uint8_t slice_id);

int nas_send_mmeinfo_req(uint8_t * imsi, uint32_t enb_ue_s1ap_id);

int
nas_proc_pdn_connectivity_res(void);

int nas_send_init_context_setup_req(uint32_t enb_ue_s1ap_id);

/*send attach accept here*/
int
nas_itti_establish_cnf_debug(struct rte_mbuf* pkt, uint32_t enb_ue_s1ap_id);

int
nas_itti_establish_cnf(uint32_t enb_ue_s1ap_id);

int
s1ap_packet_parser(struct rte_mbuf* pkt, s1ap_packet_type* s1ap_packet);

int
s1ap_mme_handle_initial_ue_message(struct rte_mbuf* pkt, uint8_t slice_id);

int
s1ap_generate_downlink_nas_transport(void);

int
s1ap_mme_handle_uplink_nas_transport(struct rte_mbuf* pkt, uint8_t msg_type, uint8_t slice_id);

int
s1ap_handle_initial_context_setup_response(struct rte_mbuf* pkt, uint8_t msg_type, uint8_t slice_id);

int
s1ap_populate_ue_context(ue_context_t * ue_context, void* packet, message_type message);

int
s1ap_handle_attach_complete_message(uint32_t enb_ue_s1ap_id, uint8_t msg_type, uint8_t slice_id);

int
s6a_generate_authentication_info_req(struct rte_mbuf* pkt);

uint32_t get_data(uint8_t* data_start, int length);

int s6a_packet_parser(struct rte_mbuf* pkt, s6a_packet_type* s6a_packet);

uint8_t * get_randp(s6a_packet_type * s6a_packet);

uint8_t * get_autnp(s6a_packet_type * s6a_packet);


void convert_imsi_to_array(uint64_t imsi, uint8_t* imsi_arr);

uint64_t get_imsi(s1ap_packet_type* s1ap_packet);

uint32_t get_enb_ue_s1ap_id(s1ap_packet_type* s1ap_packet);

uint8_t get_msg_type(s1ap_packet_type* s1ap_packet);
/*
int
s11_handle_location_update_response(struct rte_mbuf* pkt);

int s11_send_create_session_req(uint8_t * imsi);
*/

int
s11_handle_location_update_response(struct rte_mbuf* pkt, uint8_t msg_type, uint8_t slice_id);

int
s11_handle_create_session_resp(struct rte_mbuf* pkt);


int s11_send_create_session_req(uint32_t enb_ue_s1ap_id, uint8_t msg_type, uint8_t slice_id);

int
s11_send_modify_bearer_req(uint32_t enb_ue_s1ap_id, uint8_t msg_type, uint8_t slice_id);
