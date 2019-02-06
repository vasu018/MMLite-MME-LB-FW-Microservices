#include "mme_context.h"
//#include "kvs_main.h"
char name[]={"MME_CONTEXTS"};

struct context* create_mme_context(int imsi) {
	 struct context * pcontext =( struct context *)rte_zmalloc("MMECONTEXT", sizeof(struct context*), 0);
//	 pcontext->conn_state = ATTACH_REQ;
	 pcontext->imsi = imsi;
	 kvs_set(name,imsi, (void *)pcontext);
	 return pcontext;
}

struct context* fetch_mme_context_imsi(int imsi) {

	return (struct context*) kvs_get(name,imsi);
}

int delete_mme_context_imsi(int imsi) {
	struct context * pcontext = fetch_mme_context_imsi(imsi);
	if(pcontext) {
		rte_free(pcontext);
	}
  return kvs_del(name,imsi);
}
