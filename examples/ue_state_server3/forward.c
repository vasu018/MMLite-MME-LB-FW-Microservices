/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mme.h"
#include "kvs_main.h"
#include <signal.h>
#include "ue_context.h"
#include <rte_malloc.h>
#include <rte_atomic.h>


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>


#define TRUE   1
#define FALSE  0
#define PORT 8888
#define PAGE_SIZE 300

//char name[RTE_HASH_NAMESIZE] = {HASH_NAME};
//char imsi_htable[] = "imsi_ue_context_htbl";
char enb_tlb[] = "enb_ue_s1ap_id_ue_context_htbl";
int clientFileDiscriptor[20];
int serverFileDiscriptor;
//char name[RTE_HASH_NAMESIZE] = {"mytable"};


static void *s_mem(char * data, int size ){

	void * ret = rte_zmalloc("KVS", size, 0);
	if(!ret)
		return NULL;
	memcpy(ret, data, size);
	return ret;
}


static void intHandler(int val) {
    for(int i =0;i<20;i++) {
    	close(clientFileDiscriptor[i]);
    }
    close(serverFileDiscriptor);
    printf("val:%d", val);
    exit(0);
}
//In this version, server receives a request and populates the existing DB

#if 0
static char *create_buf(uint64_t key, char * temp){
	char * res = (char *) calloc(PAGE_SIZE , sizeof(char));
	int32_t retcode = -1;
	memcpy(res,&key,sizeof(uint64_t));
	char def[] = "-1";
	if(temp)
		retcode = sizeof(struct ue_context_s);//on success send the size of the structure, else give -1
	if(!temp)
		temp = def;
	//int32_t

	memcpy(res  + sizeof(uint64_t), &retcode, sizeof(int32_t));
	if(temp == def)
		memcpy(res  + sizeof(int32_t) + sizeof(uint64_t), temp, strlen(temp));
	else
		memcpy(res  + sizeof(int32_t) + sizeof(uint64_t), temp, sizeof(struct ue_context_s));
	return res;
}
#endif

static void *Server(void *args)
{
 int clientFileDiscriptor = *(int *)args;
 int nread = sizeof(uint64_t);
 char buff[300] = {0};
 uint64_t key;
 printf("\nclientFileDiscriptor :%d\n",clientFileDiscriptor);
 while(1) {
	 nread = read(clientFileDiscriptor,buff,sizeof(uint64_t));
	 printf("nread:%d\n",nread);
 	 if(nread == sizeof(uint64_t)) {
 		 key = *(uint64_t *)buff;
 	 }else{
 		 //printf("\nread returned error");
 		 break;
 	 }
 	 nread = read(clientFileDiscriptor,buff,sizeof(struct ue_context_s));
 	 if(nread == sizeof(struct ue_context_s)) {
 		 kvs_set(enb_tlb, key, s_mem(buff, sizeof(struct ue_context_s)));
 	 }else{
 		 break;
 	 }
 }
 close(clientFileDiscriptor);
 return NULL;
}




int
main(int argc, char **argv)
{
	int ret;//char b[20] = {0};
	ret = rte_eal_init(argc, argv);
	//printf("Sizeof: %lu\n", sizeof(cont));
	//return 0;
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
/*
	if(kvs_hash_init_64(imsi_htable)){
		printf("unable to create hash\n");
		goto cleanup;
	}
*/
// making few entries in the table

	//char abc[] = "100";
	//kvs_set(enb_tlb,500,s_mem(abc, strlen(abc)));



	 struct sockaddr_in sock_var;
	 serverFileDiscriptor=socket(AF_INET,SOCK_STREAM,0);

	 int i;
	 pthread_t t[20];

	 sock_var.sin_addr.s_addr=inet_addr("0.0.0.0");
	 sock_var.sin_port=8000;
	 sock_var.sin_family=AF_INET;

	 signal(SIGINT, intHandler);

	 if(bind(serverFileDiscriptor,(struct sockaddr*)&sock_var,sizeof(sock_var))>=0)
	 {
	  printf("\n socket has been created\n");
	  fflush(stdout);
	  listen(serverFileDiscriptor,0);
	  while(1)        //loop infinity
	  {
	   for(i=0;i<20;i++)      //can support 20 clients at a time
	   {
	    clientFileDiscriptor[i]=accept(serverFileDiscriptor,NULL,NULL);
	    printf("\n Connected to client %d",clientFileDiscriptor[i]);
	    pthread_create(&t[i],NULL,Server,(void *)&(clientFileDiscriptor[i]));
	   }
	  }
	  close(serverFileDiscriptor);
	 }
	 else{
	  printf("\n socket creation failed\n");
	 }


	rte_eal_mp_wait_lcore();
	return 0;
}
