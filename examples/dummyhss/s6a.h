#define MAX_AVP 10
#define RAND_LEN 16
#define XRES_LEN 8
#define AUTN_LEN 16
#define KASME_LEN 32


#define  S6A_AUTH_INFO          318
#define  S6A_LAU                316

typedef struct {
        uint32_t code;
        uint8_t flags;
        uint32_t length;
        uint32_t vendor_id;
        uint8_t kasme[KASME_LEN];
}kasme_avp_type;

typedef struct {
        uint32_t code;
        uint8_t flags;
        uint32_t length;
        uint32_t vendor_id;
        uint8_t autn[AUTN_LEN];
}autn_avp_type;

typedef struct {
        uint32_t code;
        uint8_t flags;
        uint32_t length;
        uint32_t vendor_id;
        uint8_t xres[XRES_LEN];
}xres_avp_type;

typedef struct {
        uint32_t code;
        uint8_t flags;
        uint32_t length;
        uint32_t vendor_id;
        uint8_t rand[RAND_LEN];
}rand_avp_type;

typedef struct {
        uint32_t code;
        uint8_t flags;
        uint32_t length;
	uint32_t vendor_id;
	rand_avp_type rand_avp;
	xres_avp_type xres_avp;
	autn_avp_type autn_avp;
	kasme_avp_type kasme_avp;
}eutran_vector_type;


typedef struct {
	eutran_vector_type eutran_vector;
}auth_info_type;


typedef struct {
        uint32_t avp_code;
	uint8_t avp_flags;
	uint32_t length;
	uint32_t vendor_id;
	union{
        	auth_info_type auth_info;
        }s6a_avp;
}s6a_avps_type;


typedef struct {
        uint8_t version;
	uint32_t length;
	uint8_t flag;
	uint32_t command_code;
	uint32_t application_id;
	uint32_t hop_by_hop_id;
	uint32_t end_to_end_id;
	s6a_avps_type avps[MAX_AVP];
}s6a_packet_type;
