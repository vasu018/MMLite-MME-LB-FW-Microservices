/*
 * mme_context.h
 *
 *  Created on: Apr 4, 2017
 *      Author: Vasu
 */

#ifndef OPENNETVM_EXAMPLES_DUMMYMME_MME_CONTEXT_H_
#define OPENNETVM_EXAMPLES_DUMMYMME_MME_CONTEXT_H_

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

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
#include "kvs_main.h"



enum state_t {
//	ATTACH_REQ,
	ATTACH_PROC,
	ATTACH_COMP,
//	SERVICE_REQ,
	DETACH_REQ,
	DETACH_COMP};


struct context {
	int imsi ;
	enum state_t conn_state;
};


struct context* create_mme_context(int imsi);
struct context* fetch_mme_context_imsi(int imsi);
int delete_mme_context_imsi(int imsi);


#endif /* OPENNETVM_EXAMPLES_DUMMYMME_MME_CONTEXT_H_ */
