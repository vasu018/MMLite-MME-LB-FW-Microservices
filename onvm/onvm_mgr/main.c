/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2016 George Washington University
 *            2015-2016 University of California Riverside
 *            2010-2014 Intel Corporation. All rights reserved.
 *            2016 Hewlett Packard Enterprise Development LP
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
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
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
 *
 ********************************************************************/


/******************************************************************************
                                   main.c

     File containing the main function of the manager and all its worker
     threads.

******************************************************************************/


#include <signal.h>

#include "onvm_mgr.h"
#include "onvm_stats.h"
#include "onvm_pkt.h"
#include "onvm_nf.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef INTERRUPT_SEM
struct wakeup_info *wakeup_infos;
#endif //INTERRUPT_SEM
#include "kvs_main.h"

char imsi_htable[] = "imsi_ue_context_htbl";
char s11_htable[] = "tun11_ue_context_htbl";
char mme_htable[] = "mme_ue_s1ap_id_ue_context_htbl";
char enb_htable[] = "enb_ue_s1ap_id_ue_context_htbl";
char guti_htable[] = "guti_ue_context_htbl";
char inst_htable[] = "inst_load";
char svc_lt_htable[] = "svc_lt";


uint64_t ts_table_s[100000] = {0};
uint64_t ts_table_e[100000] = {0};

/****************************Internal Declarations****************************/

// True as long as the main thread loop should keep running
static uint8_t main_keep_running = 1;

// We'll want to shut down the TX/RX threads second so that we don't
// race the stats display to be able to print, so keep this varable separate
static uint8_t worker_keep_running = 1;

static void handle_signal(int sig);

/*******************************Worker threads********************************/
/* Functions to fetch cpu usage
*/

#define BUF_MAX 1024
#define MAX_CPU 128
 
static int read_fields (FILE *fp, unsigned long long int *fields)
{
  int retval;
  char buffer[BUF_MAX];
 
 
  if (!fgets (buffer, BUF_MAX, fp))
  { perror ("Error"); }
  /* line starts with c and a string. This is to handle cpu, cpu[0-9]+ */
  retval = sscanf (buffer, "c%*s %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu",
                            &fields[0], 
                            &fields[1], 
                            &fields[2], 
                            &fields[3], 
                            &fields[4], 
                            &fields[5], 
                            &fields[6], 
                            &fields[7], 
                            &fields[8], 
                            &fields[9]); 
  if (retval == 0)
  { return -1; }
  if (retval < 4) /* Atleast 4 fields is to be read */
  {
    fprintf (stderr, "Error reading /proc/stat cpu field\n");
    return 0;
  }
  return 1;
}


//function to fetch cpu usage of a pid
FILE *pidfp = NULL;
static void readone(long long int *x) { int ret =  fscanf(pidfp, "%lld ", x); if(ret == 0) return;}
//static void readunsigned(unsigned long long *x) { fscanf(pidfp, "%llu ", x); }
static void readstr(char *x) { int ret =  fscanf(pidfp, "%s ", x); if(ret == 0) return;}
static void readchar(char *x) { int ret = fscanf(pidfp, "%c ", x);if(ret == 0) return;}


static long long int cpu_usage(int pid) {
	char buff[100] = {0};
	long long int temp ,utime, stimev, cutime, cstime;
	long long int c_utime, cstimev, ccutime, ccstime;
	char c;
	char cc[100] = {0};
	unsigned long long int delta;

	snprintf(buff, 100, "/proc/%d/stat", pid);

	pidfp = fopen (buff, "r");

	if(!pidfp) {
		return 0;
	}	

	// get start uptime


	readone(&temp);
	readstr(cc);
	readchar(&c);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);

	readone(&utime);
	readone(&stimev);
	readone(&cutime);
	readone(&cstime);

	fclose(pidfp);

	sleep(1);
	//usleep(100000);

	pidfp = fopen (buff, "r");

	if(!pidfp) {
		return 0;
	}


	// get current  uptime


	readone(&temp);
	readstr(cc);
	readchar(&c);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);
	readone(&temp);

	readone(&c_utime);
	readone(&cstimev);
	readone(&ccutime);
	readone(&ccstime);

	delta = c_utime - utime + cstimev- stimev + ccutime - cutime + ccstime - cstime;

	return delta;
}


 
/*
 * Stats thread periodically prints per-port and per-NF stats.
 */


static void
master_thread_main(void) {
        uint16_t i;
        const unsigned sleeptime = 1;

        RTE_LOG(INFO, APP, "Core %d: Running master thread \n", rte_lcore_id());


        if (stats_destination == ONVM_STATS_WEB) {
                RTE_LOG(INFO, APP, "ONVM stats can be viewed through the web console\n");
                RTE_LOG(INFO, APP, "\tTo activate, please run $ONVM_HOME/onvm_web/start_web_console.sh\n");
        }

        /* Longer initial pause so above printf is seen */
        sleep(sleeptime * 3);

        /* Loop forever: sleep always returns 0 or <= param */
        while ( main_keep_running && sleep(sleeptime) <= sleeptime) {
                onvm_nf_check_status();
                if (stats_destination != ONVM_STATS_NONE)
                        onvm_stats_display_all(sleeptime);
        }

        /* Close out file references and things */
        onvm_stats_cleanup();

        RTE_LOG(INFO, APP, "Core %d: Initiating shutdown sequence\n", rte_lcore_id());

        /* Stop all RX and TX threads */
        worker_keep_running = 0;

        /* Tell all NFs to stop */
        for (i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].info == NULL) {
                        continue;
                }
                RTE_LOG(INFO, APP, "Core %d: Notifying NF %"PRIu16" to shut down\n", rte_lcore_id(), i);
                onvm_nf_send_msg(i, MSG_STOP, NULL);
        }

        /* Wait to process all exits */
        while (num_clients > 0) {
                onvm_nf_check_status();
                RTE_LOG(INFO, APP, "Core %d: Waiting for %"PRIu16" NFs to exit\n", rte_lcore_id(), num_clients);
                sleep(sleeptime);
        }

        RTE_LOG(INFO, APP, "Core %d: Master thread done\n", rte_lcore_id());
}


/*
 * Function to receive packets from the NIC
 * and distribute them to the default service
 */
static int
rx_thread_main(void *arg) {
        uint16_t i, rx_count;
        struct rte_mbuf *pkts[PACKET_READ_SIZE];
        struct thread_info *rx = (struct thread_info*)arg;

        RTE_LOG(INFO,
                APP,
                "Core %d: Running RX thread for RX queue %d\n",
                rte_lcore_id(),
                rx->queue_id);

        for (; worker_keep_running;) {
                /* Read ports */
                for (i = 0; i < ports->num_ports; i++) {
                        rx_count = rte_eth_rx_burst(ports->id[i], rx->queue_id, \
                                        pkts, PACKET_READ_SIZE);
                        ports->rx_stats.rx[ports->id[i]] += rx_count;

                        /* Now process the NIC packets read */
                        if (likely(rx_count > 0)) {
                                // If there is no running NF, we drop all the packets of the batch.
                                if (!num_clients) {
                                        onvm_pkt_drop_batch(pkts, rx_count);
                                } else {
                                        onvm_pkt_process_rx_batch(rx, pkts, rx_count);
                                }
                        }
                }
        }

        RTE_LOG(INFO, APP, "Core %d: RX thread done\n", rte_lcore_id());

        return 0;
}


static int
tx_thread_main(void *arg) {
        struct client *cl;
        unsigned i, tx_count;
        struct rte_mbuf *pkts[PACKET_READ_SIZE];
        struct thread_info* tx = (struct thread_info*)arg;

        if (tx->first_cl == tx->last_cl - 1) {
                RTE_LOG(INFO,
                        APP,
                        "Core %d: Running TX thread for NF %d\n",
                        rte_lcore_id(),
                        tx->first_cl);
        } else if (tx->first_cl < tx->last_cl) {
                RTE_LOG(INFO,
                        APP,
                        "Core %d: Running TX thread for NFs %d to %d\n",
                        rte_lcore_id(),
                        tx->first_cl,
                        tx->last_cl-1);
        }

        for (; worker_keep_running;) {
                /* Read packets from the client's tx queue and process them as needed */
                for (i = tx->first_cl; i < tx->last_cl; i++) {
                        cl = &clients[i];
                        if (!onvm_nf_is_valid(cl))
                                continue;

			/* Dequeue all packets in ring up to max possible. */
			tx_count = rte_ring_dequeue_burst(cl->tx_q, (void **) pkts, PACKET_READ_SIZE);

                        /* Now process the Client packets read */
                        if (likely(tx_count > 0)) {
                                onvm_pkt_process_tx_batch(tx, pkts, tx_count, cl);
                        }
                }

                /* Send a burst to every port */
                onvm_pkt_flush_all_ports(tx);

                /* Send a burst to every NF */
                onvm_pkt_flush_all_nfs(tx);
        }

        RTE_LOG(INFO, APP, "Core %d: TX thread done\n", rte_lcore_id());

        return 0;
}

static void
handle_signal(int sig) {
        if (sig == SIGINT || sig == SIGTERM) {
                main_keep_running = 0;
        }
}
#if 0
static double
cpu_util( int pid) {
	FILE *fp;
	char buff[100] = {0};
	char result[100] = {0};
	double res = -1;
	printf("cpu util start with pid:%d\n",pid);
	snprintf(buff,100, "top -bn 1 |grep %d|awk '{print $9}'",pid);
	printf("buff:%s\n",buff);

	fp = popen(buff, "r");

	if(fp == NULL) {
		printf("unable to execute\n");
	}

	if(fgets(result, 99, fp) == NULL) {
		printf("cpu_util_error\n");
		pclose(fp);
		return res;
	}
	pclose(fp);
	printf("result:%s\n",result);
	res = atof(result);
	return res;
}

#endif

int queue_size[100];

float cpu_load[100];

void update_queue_size(void)
{
	cJSON *temp = jlcore->next;
	while(temp) {
		cJSON *temp2 = temp->child;
		//Iterating through all the service id's
		while(temp2){
			//Iterate through all the instance Id's
			//cJSON *temp3 = temp2->child;
			int instanceid = atoi(temp2->string);
			int ring = rte_ring_count(clients[instanceid].rx_q);
			queue_size[instanceid] = (queue_size[instanceid] + ring)/2;
			temp2 = temp2->next;
			
		}
		temp = temp->next;
	}
}

static int
update_status(void) {
	pthread_mutex_lock(&json_lock);
	cJSON *temp = jlcore->next;
	while(temp) {
		cJSON *temp2 = temp->child;
		//Iterating through all the service id's
		while(temp2){
			//Iterate through all the instance Id's
			cJSON *temp3 = temp2->child;
			int instanceid = atoi(temp2->string);
			//int ring = rte_ring_count(clients[instanceid].rx_q);
			//queue_size[instanceid] = (queue_size[instanceid] + ring)/2;
			cJSON_SetIntValue(temp3, queue_size[instanceid]);
			
			temp3 = temp3->next;
			temp3->valuedouble = cpu_usage(clients[instanceid].info->pid);
			
			temp3 = temp3->next;
			cJSON_SetIntValue(temp3, clients[instanceid].info->lcore);
			
			temp2 = temp2->next;
		}
		temp = temp->next;
	}
	pthread_mutex_unlock(&json_lock);

	//printf("exiting update_status\n");
	return 0;
}


static int
nf_queue_status_main(__attribute__((unused)) void *arg) {

// Keep trying to connect every few seconds.
	struct sockaddr_in sock_var;
	int clientFileDiscriptor=socket(AF_INET,SOCK_STREAM,0);
	sock_var.sin_addr.s_addr=inet_addr("130.245.144.30");
	//sock_var.sin_addr.s_addr=inet_addr("130.245.144.70");
	sock_var.sin_port=6000;
	sock_var.sin_family=AF_INET;
	int retrydelay = 1;
	int i = 0;
// Data structures to calculate lcore cpu util

  FILE *cpufp;
  unsigned long long int fields[10], total_tick[MAX_CPU], total_tick_old[MAX_CPU], idle[MAX_CPU], idle_old[MAX_CPU], del_total_tick[MAX_CPU], del_idle[MAX_CPU];
  int  cpus = 0, count;
  double percent_usage;
  cpufp = fopen ("/proc/stat", "r");
  if (cpufp == NULL)
  {
    perror ("Error");
  }
 
 
  while (read_fields (cpufp, fields) != -1)
  {
    for (i=0, total_tick[cpus] = 0; i<10; i++)
    { total_tick[cpus] += fields[i]; }
    idle[cpus] = fields[3]; /* idle ticks index */
    cpus++;
  }
  usleep(100000);

	/*
	 * JSON of the following form
	 * {
    "name": "HostID",
    "lcore": {
    	"lcore#" : <cpu-util>
    	....

    }
    "Service-ID": {
        "NF-ID":{
        	"queue-status": <int>
        	"cpu_util": <float>

        }
        ....
    }
}
	 *
	 *
	 *
	 */
	pthread_mutex_init(&json_lock, NULL);

	data = cJSON_CreateObject();
	cJSON_AddItemToObject(data, "name", cJSON_CreateString("Hostname"));
	cJSON_AddItemToObject(data, "lcore", jlcore = cJSON_CreateObject());
	//cJSON_AddItemToObject(data, "serviceID", jsid = cJSON_CreateObject());
/*
 * cJSON *framerate_item = cJSON_GetObjectItem(format, "frame rate");
cJSON_SetNumberValue(framerate_item, 25);

 */

	long int num_lcores = sysconf(_SC_NPROCESSORS_ONLN);
	i = 0;
    while(i <num_lcores ) {
    	//Initialize the json structure for each lcore
	char buff[10] = {0};
    	snprintf(buff,10,"%d",i);
    	cJSON_AddNumberToObject(jlcore, buff, i);
    	i++;
		
    }
	//printf("\nprint1\n%s\n",cJSON_Print(data));

	while(1) {
		 if(connect(clientFileDiscriptor,(struct sockaddr*)&sock_var,sizeof(sock_var))>=0)
		 {
			 printf("socket creation success\n");
			 retrydelay = 1;
		 } else{
			 printf("socket creation failed\n");
			 //need to retry
			 sleep(retrydelay);
			 retrydelay *=2;
			 if(retrydelay > 60) {
				 retrydelay = 60;
			 }
			 continue;
		 }

		// if connect succeeds Collect NF info and send it across
		while(1) {
			//Collect lcore info and update the utils

    			fseek (cpufp, 0, SEEK_SET);
    			fflush (cpufp);
    			for (count = 0; count < cpus; count++)
    			{
      				total_tick_old[count] = total_tick[count];
      				idle_old[count] = idle[count];
     
      				if (!read_fields (cpufp, fields))
      				{ 
						for (count = 0; count < cpus; count++)
						{
							char buff[10] = {0};
							snprintf(buff,10,"%d",count -1);
				
							cJSON *lcore_cpu_stat = cJSON_GetObjectItem(jlcore, buff);
							cJSON_SetNumberValue(lcore_cpu_stat, cpu_load[count]);
						}
						break; 
					}
 
      				for (i=0, total_tick[count] = 0; i<10; i++)
      				{ total_tick[count] += fields[i]; }
      				idle[count] = fields[3];
 
      				del_total_tick[count] = total_tick[count] - total_tick_old[count];
      				del_idle[count] = idle[count] - idle_old[count];
 
      				percent_usage = ((del_total_tick[count] - del_idle[count]) / (double) del_total_tick[count]) * 100;
					cpu_load[count] = (cpu_load[count] + percent_usage)/2;
      				if (count != 0)
      				{ //printf ("Total CPU Usage: %3.2lf%%\n", percent_usage);

					char buff[10] = {0};
    					snprintf(buff,10,"%d",count -1);
				
 					cJSON *lcore_cpu_stat = cJSON_GetObjectItem(jlcore, buff);
					cJSON_SetNumberValue(lcore_cpu_stat, cpu_load[count]);
			   //printf ("\tCPU%d Usage: %3.2lf%%\n", count - 1, percent_usage);
    				}
			}

		// End of code to update lcore cpu usage			
			//Need to write call the api to collect lcore info
			char datalen[20] = {0};
			
			//printf("\nprint2\n%s\n",cJSON_Print(data));
			
			/* First update the queue size and cpu utilization */
			//for (int i = 0;i<10000;i++)
			//{
				update_status();
				//usleep(100);
			//}

			pthread_mutex_lock(&json_lock);
			char *temp = cJSON_Print(data);
			pthread_mutex_unlock(&json_lock);
			printf("\n%s\n", temp);

			/* first write the size of data to be sent */
			snprintf(datalen,20,"%lu",strlen(temp));
			if(write(clientFileDiscriptor, datalen, 20) < 0) {

				//THis means connection is broken. Need to re-establish connection
				printf("Connection broken\n");
				free(temp);
				break;
			}


			if(write(clientFileDiscriptor, temp, strlen(temp)) < 0) {

				//THis means connection is broken. Need to re-establish connection
				printf("Connection broken\n");
				free(temp);
				break;
			}
			free(temp);
			//usleep(100);
			for(int i=0;i<10000;i++)
			{
				update_queue_size();
				usleep(1);
				
			}
			//sleep(1);
		}
		close(clientFileDiscriptor);

	}

	printf("exiting nfqueue_status_main\n");
	return 0;
}



/*******************************Main function*********************************/
//TODO: Move to apporpriate header or a different file for onvm_nf_wakeup_mgr/hdlr.c
#ifdef INTERRUPT_SEM
#include <signal.h>

unsigned nfs_wakethr[MAX_CLIENTS] = {[0 ... MAX_CLIENTS-1] = 1};

static void
register_signal_handler(void);
static inline int
whether_wakeup_client(int instance_id);
static inline void
wakeup_client(int instance_id, struct wakeup_info *wakeup_info);
static int
wakeup_nfs(void *arg);

#endif

int
main(int argc, char *argv[]) {
        unsigned cur_lcore, rx_lcores, tx_lcores;
        unsigned clients_per_tx;char name[]={"MME_CONTEXT"};char enb_tlb[] = {"ENB_TLB"};
        unsigned i;
        unsigned nfstatus = ONVM_NUM_STATUS_THREADS;
		
		memset(queue_size,0,sizeof(int) * 100);
		memset(cpu_load,0,sizeof(float) * 100);

        /* initialise the system */
        #ifdef INTERRUPT_SEM
        unsigned wakeup_lcores;
        register_signal_handler();
        #endif

        /* Reserve ID 0 for internal manager things */
        next_instance_id = 1;
        if (init(argc, argv) < 0 )
                return -1;
        RTE_LOG(INFO, APP, "Finished Process Init.\n");

        /* clear statistics */
        onvm_stats_clear_all_clients();

        /* Reserve n cores for: 1 Stats, 1 final Tx out, and ONVM_NUM_RX_THREADS for Rx */
        cur_lcore = rte_lcore_id();
        rx_lcores = ONVM_NUM_RX_THREADS;

        #ifdef INTERRUPT_SEM
        wakeup_lcores = ONVM_NUM_WAKEUP_THREADS;
        tx_lcores = rte_lcore_count() - rx_lcores - wakeup_lcores - 1;
        #else
        tx_lcores = rte_lcore_count() - rx_lcores - 1;
        #endif
        tx_lcores -= nfstatus;

        /* Offset cur_lcore to start assigning TX cores */
        cur_lcore += (rx_lcores-1);

        RTE_LOG(INFO, APP, "%d cores available in total\n", rte_lcore_count());
        RTE_LOG(INFO, APP, "%d cores available for handling manager RX queues\n", rx_lcores);
        RTE_LOG(INFO, APP, "%d cores available for handling TX queues\n", tx_lcores);
        #ifdef INTERRUPT_SEM
        RTE_LOG(INFO, APP, "%d cores available for handling wakeup\n", wakeup_lcores);
        #endif
        RTE_LOG(INFO, APP, "%d cores available for exporting nf stats\n", nfstatus);
        RTE_LOG(INFO, APP, "%d cores available for handling stats\n", 1);

        /* Evenly assign NFs to TX threads */

        /*
         * If num clients is zero, then we are running in dynamic NF mode.
         * We do not have a way to tell the total number of NFs running so
         * we have to calculate clients_per_tx using MAX_CLIENTS then.
         * We want to distribute the number of running NFs across available
         * TX threads
         */
        clients_per_tx = ceil((float)MAX_CLIENTS/tx_lcores);

        // We start the system with 0 NFs active
        num_clients = 0;

        /* Listen for ^C and docker stop so we can exit gracefully */
        signal(SIGINT, handle_signal);
        signal(SIGTERM, handle_signal);

        for (i = 0; i < tx_lcores; i++) {
                struct thread_info *tx = calloc(1, sizeof(struct thread_info));
                tx->queue_id = i;
                tx->port_tx_buf = calloc(RTE_MAX_ETHPORTS, sizeof(struct packet_buf));
                tx->nf_rx_buf = calloc(MAX_CLIENTS, sizeof(struct packet_buf));
                tx->first_cl = RTE_MIN(i * clients_per_tx + 1, (unsigned)MAX_CLIENTS);
                tx->last_cl = RTE_MIN((i+1) * clients_per_tx + 1, (unsigned)MAX_CLIENTS);
                cur_lcore = rte_get_next_lcore(cur_lcore, 1, 1);
                if (rte_eal_remote_launch(tx_thread_main, (void*)tx,  cur_lcore) == -EBUSY) {
                        RTE_LOG(ERR,
                                APP,
                                "Core %d is already busy, can't use for client %d TX\n",
                                cur_lcore,
                                tx->first_cl);
                        return -1;
                }
        }

        /* Launch RX thread main function for each RX queue on cores */
        for (i = 0; i < rx_lcores; i++) {
                struct thread_info *rx = calloc(1, sizeof(struct thread_info));
                rx->queue_id = i;
                rx->port_tx_buf = NULL;
                rx->nf_rx_buf = calloc(MAX_CLIENTS, sizeof(struct packet_buf));
                cur_lcore = rte_get_next_lcore(cur_lcore, 1, 1);
                if (rte_eal_remote_launch(rx_thread_main, (void *)rx, cur_lcore) == -EBUSY) {
                        RTE_LOG(ERR,
                                APP,
                                "Core %d is already busy, can't use for RX queue id %d\n",
                                cur_lcore,
                                rx->queue_id);
                        return -1;
                }
        }
        /* Launch export queue status server on nfstatus cores */
        for (i = 0; i < nfstatus; i++) {

                cur_lcore = rte_get_next_lcore(cur_lcore, 1, 1);
                if (rte_eal_remote_launch(nf_queue_status_main, NULL, cur_lcore) == -EBUSY) {

                        return -1;
                }
        }


        /* starting the KV stores*/
    	if(kvs_hash_init(name)){
    		 RTE_LOG(ERR, APP, "\nKV notinited\n");

    	} else {

    		 RTE_LOG(INFO, APP, "\nKV inited\n");
    	}
    	
	if(kvs_hash_init(enb_tlb)){
    		 RTE_LOG(ERR, APP, "\nKV notinited\n");

    	}else {
    		 RTE_LOG(INFO, APP, "\nKV inited\n");
    	}
    	
		kvs_hash_init_64(imsi_htable);
    	kvs_hash_init(s11_htable);
    	kvs_hash_init(mme_htable);
    	kvs_hash_init(enb_htable);
    	kvs_hash_init(guti_htable);
    	kvs_hash_init(inst_htable);
    	for(int j =1;j<=MAX_CLIENTS;j++) {
    		int16_t *limit =  (int16_t *) rte_malloc(NULL,sizeof(int16_t),0);
    		*limit = 0;
    		kvs_set(inst_htable,j,limit);
    	}
    	kvs_hash_init(svc_lt_htable);
    	for(int j =1;j<=MAX_SERVICES;j++) {
    		svc_load_info_t *info =  (svc_load_info_t *) rte_malloc(NULL,sizeof(svc_load_info_t),0);
    		info->type = SVC_LOAD_INFO_RR;
//    		info->value = 0;
    		rte_atomic64_init(&(info->value));
    		//enable below for LI
    		//rte_atomic64_set(&(info->value), (CLIENT_QUEUE_RINGSIZE - (CLIENT_QUEUE_RINGSIZE>>3)) );
    		kvs_set(svc_lt_htable,j,info);
    	}

        #ifdef INTERRUPT_SEM
        int clients_per_wakethread = ceil((unsigned)MAX_CLIENTS / wakeup_lcores);
        wakeup_infos = (struct wakeup_info *)calloc(wakeup_lcores, sizeof(struct wakeup_info));
        if (wakeup_infos == NULL) {
                printf("can not alloc space for wakeup_info\n");
                exit(1);
        }
        for (i = 0; i < wakeup_lcores; i++) {
                wakeup_infos[i].first_client = RTE_MIN(i * clients_per_wakethread + 1, (unsigned)MAX_CLIENTS);
                wakeup_infos[i].last_client = RTE_MIN((i+1) * clients_per_wakethread + 1, (unsigned)MAX_CLIENTS);
                cur_lcore = rte_get_next_lcore(cur_lcore, 1, 1);
                rte_eal_remote_launch(wakeup_nfs, (void*)&wakeup_infos[i], cur_lcore);
                printf("wakeup lcore_id=%d, first_client=%d, last_client=%d\n", cur_lcore, wakeup_infos[i].first_client, wakeup_infos[i].last_client);
        }

        /* this change is Not needed anymore
        cur_lcore = rte_get_next_lcore(cur_lcore, 1, 1);
        printf("monitor_lcore=%u\n", cur_lcore);
        rte_eal_remote_launch(monitor, NULL, cur_lcore);
        */
        #endif

        /* Master thread handles statistics and NF management */
        master_thread_main();

        /* deinit the KV stores */
        kvs_hash_delete(name);
    	kvs_hash_delete(imsi_htable);
    	kvs_hash_delete(s11_htable);
    	kvs_hash_delete(mme_htable);
    	kvs_hash_delete(enb_htable);
    	kvs_hash_delete(guti_htable);

    	for(int j =1;j<=MAX_CLIENTS;j++) {
    		int16_t *limit =  (int16_t *) kvs_get(inst_htable,j);
    		rte_free(limit);

    	}
    	kvs_hash_delete(inst_htable);

    	for(int j =1;j<=MAX_SERVICES;j++) {
    		svc_load_info_t *info =  (svc_load_info_t *) kvs_get(svc_lt_htable,j);
    		rte_free(info);

    	}
    	kvs_hash_delete(svc_lt_htable);

    	//Write the values into a file

    	FILE * fp = fopen("dump.txt", "wb+");
    	for(int i =1;i<10000;i++){
    		if((ts_table_s[i] == 0)|| (ts_table_s[i]==0))
    			continue;
    		fprintf(fp, "%f,",(float)(ts_table_e[i] - ts_table_s[i])*1000/rte_get_tsc_hz());
    	}
    	fclose(fp);
        return 0;
}

/*******************************Helper functions********************************/
#ifdef INTERRUPT_SEM
#define WAKEUP_THRESHOLD 1
static inline int
whether_wakeup_client(int instance_id)
{
        uint16_t cur_entries;
        if (clients[instance_id].rx_q == NULL) {
                return 0;
        }
        cur_entries = rte_ring_count(clients[instance_id].rx_q);
        if (cur_entries >= nfs_wakethr[instance_id]){
                return 1;
        }
        return 0;
}

static inline void
wakeup_client(int instance_id, struct wakeup_info *wakeup_info)
{
        if (whether_wakeup_client(instance_id) == 1) {
                if (rte_atomic16_read(clients[instance_id].shm_server) ==1) {
                        wakeup_info->num_wakeups += 1;
                        rte_atomic16_set(clients[instance_id].shm_server, 0);
                        sem_post(clients[instance_id].mutex);
                }
        }
}

static int
wakeup_nfs(void *arg)
{
        struct wakeup_info *wakeup_info = (struct wakeup_info *)arg;
        unsigned i;

        /*
        if (wakeup_info->first_client == 1) {
                wakeup_info->first_client += ONVM_SPECIAL_NF;
        }
        */
/* Vasu: if different NF's have different priorities */
        while (true) {
                for (i = wakeup_info->first_client; i < wakeup_info->last_client; i++) {
                        wakeup_client(i, wakeup_info);
                }
        }

        return 0;
}

static void signal_handler(int sig, siginfo_t *info, void *secret) {
        int i;
        (void)info;
        (void)secret;

        //2 means terminal interrupt, 3 means terminal quit, 9 means kill and 15 means termination
        if (sig <= 15) {
                // handle for all clients or check for onvm_nf_is_valid(). Not needed!
                for (i = 1; i < MAX_CLIENTS; i++) {
                        sem_close(clients[i].mutex);
                        sem_unlink(clients[i].sem_name);
                }
                #ifdef MONITOR
//                rte_free(port_stats);
//                rte_free(port_prev_stats);
                #endif
        }

        exit(1);
}
static void
register_signal_handler(void) {
        unsigned i;
        struct sigaction act;
        memset(&act, 0, sizeof(act));
        sigemptyset(&act.sa_mask);
        act.sa_flags = SA_SIGINFO;
        act.sa_handler = (void *)signal_handler;

        for (i = 1; i < 31; i++) {
                sigaction(i, &act, 0);
        }
}
#endif

