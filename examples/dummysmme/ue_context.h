#ifndef OPENNETVM_EXAMPLES_DUMMYMME_UE_CONTEXT_H_
#define OPENNETVM_EXAMPLES_DUMMYMME_UE_CONTEXT_H_

#define BEARERS_PER_UE (11)
#define MSISDN_LENGTH (15)

#define  bool uint8_t

//        ue_context_t * ue_context;

typedef enum {
    INDEX_ATTACH_REQ_IN = 0,
    INDEX_ATTACH_AUTH_PARAMS_OUT,
    INDEX_ATTACH_AUTH_PARAMS_IN,
    INDEX_ATTACH_AUTH_REQ_OUT,
    INDEX_ATTACH_AUTH_RSP_IN,
    INDEX_ATTACH_NAS_SECURITY_REQ_OUT,
    INDEX_ATTACH_NAS_SECURITY_RSP_IN,
    INDEX_ATTACH_LOCATION_UPDATE_REQ_OUT,
    INDEX_ATTACH_LOCATION_UPDATE_RSP_IN,
    INDEX_ATTACH_CREATE_SESSION_OUT,
    INDEX_ATTACH_CREATE_SESSION_IN,
    INDEX_ATTACH_ACCEPT_OUT,
    INDEX_ATTACH_COMPLETE_IN,
    INDEX_ATTACH_MODIFY_BEARER_OUT,
    INDEX_ATTACH_MODIFY_BEARER_IN,
/*    INDEX_SERVICE_REQ_IN,
    INDEX_SERVICE_AUTH_REQ_IN,
    INDEX_SERVICE_NAS_SECURITY_REQ_IN,
    INDEX_SERVICE_INIT_CONTEXT_SETUP_IN,
    INDEX_SERVICE_MODIFY_BEARER_REQ_IN,
    INDEX_MODIFY_BEARER_REQ_IN,*/
    MAX_INDEX
}time_array_index_type;




typedef enum {
    UE_STATE_ATTACH_REQ = 0,
    UE_STATE_ATTACH_AUTH_PARAMS,
    UE_STATE_ATTACH_AUTH_REQ,
    UE_STATE_ATTACH_NAS_SECURITY_REQ,
    UE_STATE_ATTACH_LOCATION_UPDATE,
    UE_STATE_ATTACH_CREATE_SESSION,
    UE_STATE_ATTACH_COMPLETE,
    UE_STATE_SERVICE_REQ,
    UE_STATE_SERVICE_AUTH_REQ,
    UE_STATE_SERVICE_NAS_SECURITY_REQ,
    UE_STATE_SERVICE_INIT_CONTEXT_SETUP,
    UE_STATE_SERVICE_MODIFY_BEARER_REQ,
    UE_STATE_TAU_REQ
}conn_state_type;


typedef struct ue_context_s {
  /* Basic identifier for ue. IMSI is encoded on maximum of 15 digits of 4 bits,
   * so usage of an unsigned integer on 64 bits is necessary.
   */
  uint16_t 	   udp_port;
  uint32_t 	   src_ip;
  conn_state_type  conn_state;	   
  double 	   time_stamp[MAX_INDEX];
  uint64_t         imsi;                        // set by nas_auth_param_req_t
  uint8_t          slice_id;
#define IMSI_UNAUTHENTICATED  (0x0)
#define IMSI_AUTHENTICATED    (0x1)
  /* Indicator to show the IMSI authentication state */
  unsigned               imsi_auth:1;                 // set by nas_auth_resp_t

  uint64_t      enb_s1ap_id_key; // key uniq among all connected eNBs
  uint32_t       enb_ue_s1ap_id;  //:24;
  uint32_t       mme_ue_s1ap_id;
  uint32_t        sctp_assoc_id_key;


#define SUBSCRIPTION_UNKNOWN    0x0
#define SUBSCRIPTION_KNOWN      0x1
  unsigned               subscription_known:1;        // set by S6A UPDATE LOCATION ANSWER
  uint8_t                msisdn[MSISDN_LENGTH+1];     // set by S6A UPDATE LOCATION ANSWER
  uint8_t                msisdn_length;               // set by S6A UPDATE LOCATION ANSWER

//  mm_state_t             mm_state;                    // not set/read //ENUM
  /* Globally Unique Temporary Identity */
  bool                   is_guti_set;                 // is guti has been set
//  guti_t                 guti;                        // guti.gummei.plmn set by nas_auth_param_req_t //struct
  // read by S6A UPDATE LOCATION REQUEST
//  me_identity_t          me_identity;                 // not set/read except read by display utility //struct

  /* TODO: Add TAI list */

  /* Last known cell identity */
//  ecgi_t                  e_utran_cgi;                 // set by nas_attach_req_t
  // read for S11 CREATE_SESSION_REQUEST
  /* Time when the cell identity was acquired */
  time_t                 cell_age;                    // set by nas_auth_param_req_t

  /* TODO: add csg_id */
  /* TODO: add csg_membership */

//  network_access_mode_t  access_mode;                  // set by S6A UPDATE LOCATION ANSWER //ENUM

  /* TODO: add ue radio cap, ms classmarks, supported codecs */
  /* TODO: add ue network capability, ms network capability */
  /* TODO: add selected NAS algorithm */

  /* TODO: add DRX parameter */

//  apn_config_profile_t   apn_profile;                  // set by S6A UPDATE LOCATION ANSWER
  uint32_t                  access_restriction_data;      // set by S6A UPDATE LOCATION ANSWER
//  subscriber_status_t    sub_status;                   // set by S6A UPDATE LOCATION ANSWER
//  ambr_t                 subscribed_ambr;              // set by S6A UPDATE LOCATION ANSWER
//  ambr_t                 used_ambr;

  uint32_t        rau_tau_timer;               // set by S6A UPDATE LOCATION ANSWER

  /* Store the radio capabilities as received in S1AP UE capability indication
   * message.
   */
  //char                  *ue_radio_capabilities;       // not set/read
  //int                    ue_radio_cap_length;         // not set/read

  uint32_t                 mme_s11_teid;                // set by mme_app_send_s11_create_session_req
  uint32_t                 sgw_s11_teid;                // set by S11 CREATE_SESSION_RESPONSE
//  PAA_t                  paa;                         // set by S11 CREATE_SESSION_RESPONSE

  // temp
  char                   pending_pdn_connectivity_req_imsi[16];
  uint8_t                pending_pdn_connectivity_req_imsi_length;
//  bstring                pending_pdn_connectivity_req_apn;
//  bstring                pending_pdn_connectivity_req_pdn_addr;
  int                    pending_pdn_connectivity_req_pti;
  unsigned               pending_pdn_connectivity_req_ue_id;
//  network_qos_t          pending_pdn_connectivity_req_qos;
//  protocol_configuration_options_t   pending_pdn_connectivity_req_pco;
  void                  *pending_pdn_connectivity_req_proc_data;
  int                    pending_pdn_connectivity_req_request_type;
  /*WINGSLAB_STONY eNB IP Address*/
  uint32_t              eNB_address;

  uint8_t                  default_bearer_id;
//  bearer_context_t       eps_bearers[BEARERS_PER_UE];
} ue_context_t;



#endif
