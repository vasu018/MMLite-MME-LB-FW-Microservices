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

#define TRUE   1
#define FALSE  0
#define PORT 8888
#define PAGE_SIZE 300

//char name[RTE_HASH_NAMESIZE] = {HASH_NAME};
//char imsi_htable[] = "imsi_ue_context_htbl";
char enb_tlb[] = "enb_ue_s1ap_id_ue_context_htbl";
//char name[RTE_HASH_NAMESIZE] = {"mytable"};


uv_loop_t *loop;

/*
static void *s_mem(char * data, int size ){

	void * ret = rte_zmalloc("KVS", size, 0);
	if(!ret)
		return NULL;
	memcpy(ret, data, size);
	return ret;
}*/

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

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, struct uv_buf_t *buf) {
	if (!handle)
		return ;
  *buf = uv_buf_init((char*) calloc(suggested_size,1), suggested_size);
}

static void echo_write(uv_write_t *req, int status) {
  if (status == -1) {
    fprintf(stderr, "Write error!\n");
  }

  char *base = (char*) req->data;
  //fprintf(stdout, "printing base %p\n",base);
  if(base){
	  uint64_t key = *(uint64_t *)req->data;
	  base += sizeof(uint64_t) + sizeof(int32_t);
	  //fprintf(stdout, "printing key:%lu data:%s\n", key, base);
	  //kvs_del_64(imsi_htable, key);
	  kvs_del(enb_tlb, key);
  }

  free(req->data);
  free(req);
}
//#pragma GCC diagnostic push  // require GCC 4.6
//#pragma GCC diagnostic ignored "-Wcast-qual"
static void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
  if (nread == -1) {
    fprintf(stderr, "Read error!\n");
    uv_close((uv_handle_t*)client, NULL);
    return;
  }
  uv_write_t *write_req = (uv_write_t*)malloc(sizeof(uv_write_t));
  uv_buf_t ubuf;
  uv_buf_t *wbuf = NULL;
  //printf("%ld\n",nread);
  if(nread == sizeof(uint64_t)){

	  //TODO:need to add support for htons
	  //fprintf(stdout, "received %lu\n",*(uint64_t *)buf->base);

	  //buf->base = NULL;
	  //char * temp = (char *)kvs_get_64(imsi_htable, *(uint64_t *)buf->base);
	  char * temp = (char *)kvs_get(enb_tlb, *(uint64_t *)buf->base);
	  char * tmp = create_buf(*(uint64_t *)buf->base, temp);

	  free(buf->base);
	  //free(buf);
	  //fprintf(stdout, "fetched %s\n",tmp);
	  write_req->data = (void *)(tmp);
	  //ubuf = uv_buf_init(tmp,strlen(tmp));

	  ubuf = uv_buf_init(tmp,PAGE_SIZE);
	  wbuf = &ubuf;
	  uv_write(write_req, client, wbuf, 1, echo_write);

  } else if (nread < 0) {
	  uv_close((uv_handle_t*) client, NULL);
  }
  else {
	  write_req->data = (void*)(buf->base);
	  uv_write(write_req, client, buf, 1, echo_write);
  }

  //write_req->data = (void*)(buf->base);
  //uv_write(write_req, client, wbuf, 1, echo_write);
}
//#pragma GCC diagnostic pop   // require GCC 4.6

static void on_new_connection(uv_stream_t *server, int status) {
  if (status == -1) {
    return;
  }

  uv_tcp_t *client = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
  uv_tcp_init(loop, client);
  if (uv_accept(server, (uv_stream_t*) client) == 0) {
    uv_read_start((uv_stream_t*) client, alloc_buffer, echo_read);
  }
  else {
    uv_close((uv_handle_t*) client, NULL);
  }
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
	/*
	char abc[] = "100";
	kvs_set_64(imsi_htable,500,s_mem(abc, strlen(abc)));
	*/
	loop = uv_default_loop();

	uv_tcp_t server;
	uv_tcp_init(loop, &server);

	struct sockaddr_in bind_addr;
	uv_ip4_addr("0.0.0.0", 7000, &bind_addr);
	uv_tcp_bind(&server, (const struct sockaddr *)&bind_addr, 0);
	int r = uv_listen((uv_stream_t*) &server, 128, on_new_connection);
	if (r) {
		fprintf(stderr, "Listen error!\n");
		return 1;
	}
	return uv_run(loop, UV_RUN_DEFAULT);

	rte_eal_mp_wait_lcore();
	return 0;
}
