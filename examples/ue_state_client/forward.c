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


char imsi_htable[] = "imsi_ue_context_htbl";
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

static void on_close(uv_handle_t* handle);
static void on_connect(uv_connect_t* req, int status);
static void on_write(uv_write_t* req, int status);
void on_read(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf);
int pull (char *hostname, uint64_t key);


static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, struct uv_buf_t *buf) {
	if (!handle)
		return ;
  *buf = uv_buf_init((char*) calloc(suggested_size,1), suggested_size);
}


void on_close(uv_handle_t* handle  __attribute__ ((unused)) )
{
	/*
	if(handle)
		printf(" value of handle->data %p.",handle->data);
		*/
}

void on_write(uv_write_t* req  __attribute__ ((unused)), int status)
{
	wcount++;
  if (status) {
    fprintf(stdout, "uv_write error: %s\n", uv_strerror(status));
	return;
  }
  //uv_close((uv_handle_t*)req->handle, on_close);
}
void on_read(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf)
{
	//rcount++;
	rte_atomic32_inc(&rcount);
	if(nread >= 0) {
		//printf("read: %s\n", tcp->data);
		char *data = buf->base;
		uint64_t key = *(uint64_t *)data;
		data += sizeof(uint64_t);
		int32_t retcode = *(int32_t *)data;
		data += sizeof(int32_t);
		//printf("read: key:%lu data:%s\n",key, data);
		//kvs_set_64(imsi_htable, key, s_mem(data,retcode));
		if(retcode != -1) {
			kvs_set(enb_tlb, key, s_mem(data,retcode));
			rte_atomic32_inc(&success);
		} else {
			fprintf(stderr, "got -1 no entry\n");
			rte_atomic32_inc(&fail);
		}
	}
	//else {
		//we got an EOF
    uv_close((uv_handle_t*)tcp, on_close);
	//}

	//cargo-culted
	free(buf->base);
}

void on_connect(uv_connect_t* connection, int status)
{
	ccount++;
	if (status) {
	    fprintf(stdout, "on_connect error: %s\n", uv_strerror(status));
			return;
	}
	//printf("connected with data %d.\n", *(int *)(connection->data));

	uv_stream_t* stream = connection->handle;

	//char req_str[] = "a\n";
	void * req_str = connection->data;

	uv_buf_t buffer = uv_buf_init(req_str,sizeof(uint64_t));

	uv_write_t request;

	uv_write(&request, stream, &buffer, 1, on_write);
	uv_read_start(stream, alloc_buffer, on_read);
}



int pull (char *hostname, uint64_t key){
	uv_tcp_t socket;
	uv_loop_t *loop = uv_default_loop();
	if (!loop) {
		return -1;
	}
	uv_tcp_init(loop, &socket);
	uv_tcp_keepalive(&socket, 1, 60);
	//printf("key:%lu\n",key);
	loop->data = malloc(sizeof(uint64_t));
	*(uint64_t *)loop->data = key;
	struct sockaddr_in dest;
	uv_ip4_addr(hostname, 7000, &dest);

	uv_connect_t connect;
	connect.data = loop->data;
	uv_tcp_connect(&connect, &socket, (const struct sockaddr *)& dest, on_connect);
//	if(ccount == 28230)
//		printf("Entry\n");
	uv_run(loop, UV_RUN_DEFAULT);
	uv_loop_close(loop);
<<<<<<< HEAD
	usleep(5000);
=======
#if 0
>>>>>>> d8aec924c9f177eaa3e21b058529094910548d17
	printf("status rcount:%d wcount:%lld ccount:%lld\n", rte_atomic32_read(&rcount), wcount, ccount);
#endif
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
	
    	for(int i = 0;i<threadnum;i++) {
		for(int j = 0; j <serialseed;j++) {
    			if(argv[1] != NULL )
    				pull( argv[1],(threadseed + i)*10000 + j );
    			else
    				pull( host, (threadseed + i)*10000 + j);
		}
    	}
	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    	printf("all done time taken = %f\n", cpu_time_used);
    	printf("success:%d fail:%d\n",rte_atomic32_read(&success),rte_atomic32_read(&fail));

	rte_eal_mp_wait_lcore();
	return 0;
}
