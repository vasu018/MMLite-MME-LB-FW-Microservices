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
#include <unistd.h>
#include <time.h>
#include <rte_atomic.h>


char enb_tlb[] = "enb_ue_s1ap_id_ue_context_htbl";
#define PAGE_SIZE 300//512

//int flag = 1;
rte_atomic32_t rcount = RTE_ATOMIC32_INIT(0);
rte_atomic32_t success = RTE_ATOMIC32_INIT(0);
rte_atomic32_t fail = RTE_ATOMIC32_INIT(0);
long long int wcount = 0;
long long int ccount = 0;


static void *s_mem(char * data, int size ){

	void * ret = rte_zmalloc("KVS", size, 0);
	if(!ret)
		return NULL;
	memcpy(ret, data, size);
	return ret;
}




static int pull (int fd, uint64_t key){
	char  buff[sizeof(uint64_t)] = {0};
	char retbuff[PAGE_SIZE] = {0};
	memcpy(buff, &key, sizeof(uint64_t));

	write(fd,buff,sizeof(uint64_t));
	int nread = read(fd,retbuff,PAGE_SIZE);
	if(nread <= 0) {
		printf("\nread returned error\n");
		return 0;
	}

	char *data = retbuff;
	key = *(uint64_t *)data;
	data += sizeof(uint64_t);
	int32_t retcode = *(int32_t *)data;
	data += sizeof(int32_t);
	//printf("read: key:%lu data:%s\n",key, data);
	//kvs_set_64(imsi_htable, key, s_mem(data,retcode));
	if(retcode != -1) {
		//printf("\n data:%s\n",data);
		kvs_set(enb_tlb, key, s_mem(data,retcode));
		rte_atomic32_inc(&success);
	} else {
		fprintf(stderr, "got -1 no entry\n");
		rte_atomic32_inc(&fail);
	}


	return 0;
}

int
main(int argc, char **argv)
{
	int ret;
	clock_t start, end;
	double cpu_time_used;
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
	argc -= ret; argv += ret;
	//RTE_LOG(INFO, APP, "init\n");
	//fprintf(stdout, "init: argc:%d %s\n", argc, (char *)(argv[1]));
    char host[] = "127.0.0.1";
    	//524288
	start = clock();

	int threadnum =  0;
	int threadseed = 0;
	int serialseed = 0;
	if(argv[2] != NULL)
		threadnum = atoi(argv[2]);
	if(argv[3] != NULL)
		serialseed = atoi(argv[3]);
	if(argv[4] != NULL)
		threadseed = atoi(argv[4]);
	
	 struct sockaddr_in sock_var;
	 int clientFileDiscriptor=socket(AF_INET,SOCK_STREAM,0);
	 //char str_clnt[20],str_ser[20];
	 if(argv[1] != NULL )
		sock_var.sin_addr.s_addr=inet_addr(argv[1]);
	 else
		sock_var.sin_addr.s_addr=inet_addr(host);

	 sock_var.sin_port=8000;
	 sock_var.sin_family=AF_INET;

	 if(connect(clientFileDiscriptor,(struct sockaddr*)&sock_var,sizeof(sock_var))>=0)
	 {
		 printf("socket creation success\n");
	 } else{
		 printf("socket creation failed\n");
	 }
	 printf("%d %d %d\n",threadnum, serialseed, threadseed);
	 //pull( clientFileDiscriptor,500);
#if 1
    	for(int i = 0;i<threadnum;i++) {
		for(int j = 0; j <serialseed;j++) {
				pull( clientFileDiscriptor,(threadseed + i)*10000 + j );
			}
    	}
#endif
    close(clientFileDiscriptor);
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    	printf("all done time taken = %f\n", cpu_time_used);
    	printf("success:%d fail:%d\n",rte_atomic32_read(&success),rte_atomic32_read(&fail));

	rte_eal_mp_wait_lcore();
	return 0;
}
