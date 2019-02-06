/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2016 George Washington University
 *            2015-2016 University of California Riverside
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

                                  onvm_nflib.c


                  File containing all functions of the NF API


******************************************************************************/


/***************************Standard C library********************************/


#include <getopt.h>
#include <signal.h>

//#ifdef INTERRUPT_SEM  //move maro to makefile, otherwise uncomemnt or need to include these after including common.h
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <semaphore.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>

//#endif //INTERRUPT_SEM

/*****************************Internal headers********************************/


#include "onvm_nflib.h"
#include "onvm_includes.h"
#include "onvm_sc_common.h"
#include "onvm_common.h"


/**********************************Macros*************************************/


// Number of packets to attempt to read from queue
#define PKT_READ_SIZE  ((uint16_t)128)

// Possible NF packet consuming modes
#define NF_MODE_UNKNOWN 0
#define NF_MODE_SINGLE 1
#define NF_MODE_RING 2

typedef int(*pkt_handler)(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta);

/******************************Global Variables*******************************/


// ring used for NF -> mgr messages (like startup & shutdown)
static struct rte_ring *mgr_msg_queue;

// ring used for mgr -> NF messages
static struct rte_ring *nf_msg_ring;


// rings used to pass packets between NFlib and NFmgr
static struct rte_ring *tx_ring, *rx_ring;


// shared data from server. We update statistics here
static volatile struct client_tx_stats *tx_stats;


// Shared data for client info
extern struct onvm_nf_info *nf_info;


// Shared pool for all clients info
static struct rte_mempool *nf_info_mp;

// Shared pool for mgr <--> NF messages
static struct rte_mempool *nf_msg_pool;


// User-given NF Client ID (defaults to manager assigned)
static uint16_t initial_instance_id = NF_NO_ID;


// User-given NF Client name (defaults to "client")
static char client_name[ONVM_NF_CLIENT_NAME] = "Client";

char *client_name_extern = NULL;

// User supplied service ID
static uint16_t service_id = -1;


// True as long as the NF should keep processing packets
static uint8_t keep_running = 1;


// Mode this NF is running in (single packet, or direct ring manipulation)
static uint8_t nf_mode = NF_MODE_UNKNOWN;


// Shared data for default service chain
static struct onvm_service_chain *default_chain;


//Variables to fetch the cpu usage
static struct rusage usage;
static struct timeval start, start_c;
//static struct onvm_nf_stats_info stats_info;

#ifdef INTERRUPT_SEM
// to track packets per NF <used for sampling computation cost>
uint64_t counter = 0;

// flag (shared mem variable) to track state of NF and trigger wakeups
// flag_p=1 => NF sleeping (waiting on semaphore)
// flag_p=0 => NF is running and processing (not waiting on semaphore)
static rte_atomic16_t *flag_p;

// Mutex for sem_wait
static sem_t *mutex;
#endif  //INTERRUPT_SEM

/***********************Internal Functions Prototypes*************************/


/*
 * Function that initialize a nf info data structure.
 *
 * Input  : the tag to name the NF
 * Output : the data structure initialized
 *
 */
static struct onvm_nf_info *
onvm_nflib_info_init(const char *tag);


/*
 * Function printing an explanation of command line instruction for a NF.
 *
 * Input : name of the executable containing the NF
 *
 */
static void
onvm_nflib_usage(const char *progname);


/*
 * Function that parses the global arguments common to all NFs.
 *
 * Input  : the number of arguments (following C standard library convention)
 *          an array of strings representing these arguments
 * Output : an error code
 *
 */
int
onvm_nflib_parse_args(int argc, char *argv[]);


/*
* Signal handler to catch SIGINT.
*
* Input : int corresponding to the signal catched
*
*/
static void
onvm_nflib_handle_signal(int sig);

/*
 * Check if there are packets in this NF's RX Queue and process them
 */
static inline void
onvm_nflib_dequeue_packets(void **pkts, struct onvm_nf_info *info, pkt_handler handler) __attribute__((always_inline));

/*
 * Check if there is a message available for this NF and process it
 */
static inline void
onvm_nflib_dequeue_messages(void) __attribute__((always_inline));

/*
 * Set this NF's status to not running and release memory
 *
 * Input: Info struct corresponding to this NF
 */
static void
onvm_nflib_cleanup(void);

#ifdef INTERRUPT_SEM
/*
 * Function to initalize the shared cpu support
 *
 * Input  : Number of NF instances
 */
static void
init_shared_cpu_info(uint16_t instance_id);
#endif  //INTERRUPT_SEM


/*Api to fetch cpu usage
 *
 */
static double fetch_cpu_usage(void);

/************************************API**************************************/


int
onvm_nflib_init(int argc, char *argv[], const char *nf_tag) {
        const struct rte_memzone *mz;
        const struct rte_memzone *mz_scp;
        struct rte_mempool *mp;
        struct onvm_service_chain **scp;
        struct onvm_nf_msg *startup_msg;
        int retval_eal, retval_parse, retval_final;

        if ((retval_eal = rte_eal_init(argc, argv)) < 0)
                return -1;
        /* Make entry for the start time*
         * */
        gettimeofday(&start_c, NULL);
        getrusage(RUSAGE_SELF, &usage);
        start.tv_sec = usage.ru_utime.tv_sec;
        start.tv_usec = usage.ru_utime.tv_usec;

        /* Modify argc and argv to conform to getopt rules for parse_nflib_args */
        argc -= retval_eal; argv += retval_eal;

        /* Reset getopt global variables opterr and optind to their default values */
        opterr = 0; optind = 1;

        if ((retval_parse = onvm_nflib_parse_args(argc, argv)) < 0)
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

        /*
         * Calculate the offset that the nf will use to modify argc and argv for its
         * getopt call. This is the sum of the number of arguments parsed by
         * rte_eal_init and parse_nflib_args. This will be decremented by 1 to assure
         * getopt is looking at the correct index since optind is incremented by 1 each
         * time "--" is parsed.
         * This is the value that will be returned if initialization succeeds.
         */
        retval_final = (retval_eal + retval_parse) - 1;

        /* Reset getopt global variables opterr and optind to their default values */
        opterr = 0; optind = 1;

        /* Lookup mempool for nf_info struct */
        nf_info_mp = rte_mempool_lookup(_NF_MEMPOOL_NAME);
        if (nf_info_mp == NULL)
                rte_exit(EXIT_FAILURE, "No Client Info mempool - bye\n");

        /* Lookup mempool for NF messages */
        nf_msg_pool = rte_mempool_lookup(_NF_MSG_POOL_NAME);
        if (nf_msg_pool == NULL)
                rte_exit(EXIT_FAILURE, "No NF Message mempool - bye\n");

        /* Initialize the info struct */
        nf_info = onvm_nflib_info_init(nf_tag);

        mp = rte_mempool_lookup(PKTMBUF_POOL_NAME);
        if (mp == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get mempool for mbufs\n");

        mz = rte_memzone_lookup(MZ_CLIENT_INFO);
        if (mz == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get tx info structure\n");
        tx_stats = mz->addr;

        mz_scp = rte_memzone_lookup(MZ_SCP_INFO);
        if (mz_scp == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get service chain info structre\n");
        scp = mz_scp->addr;
        default_chain = *scp;

        onvm_sc_print(default_chain);

        mgr_msg_queue = rte_ring_lookup(_MGR_MSG_QUEUE_NAME);
        if (mgr_msg_queue == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get nf_info ring");

        /* Put this NF's info struct onto queue for manager to process startup */
        if (rte_mempool_get(nf_msg_pool, (void**)(&startup_msg)) != 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_exit(EXIT_FAILURE, "Cannot create startup msg");
        }

        startup_msg->msg_type = MSG_NF_STARTING;
        startup_msg->msg_data = nf_info;

        strncpy(nf_info->client_name, client_name, strlen(client_name)); 
        RTE_LOG(INFO, APP, "Client name : %s\n", client_name);

        if (rte_ring_enqueue(mgr_msg_queue, startup_msg) < 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_mempool_put(nf_msg_pool, startup_msg);
                rte_exit(EXIT_FAILURE, "Cannot send nf_info to manager");
        }

        /* Wait for a client id to be assigned by the manager */
        RTE_LOG(INFO, APP, "Waiting for manager to assign an ID...\n");
        for (; nf_info->status == (uint16_t)NF_WAITING_FOR_ID ;) {
                sleep(1);
        }

        /* This NF is trying to declare an ID already in use. */
        if (nf_info->status == NF_ID_CONFLICT) {
                rte_mempool_put(nf_info_mp, nf_info);
                rte_exit(NF_ID_CONFLICT, "Selected ID already in use. Exiting...\n");
        } else if(nf_info->status == NF_NO_IDS) {
                rte_mempool_put(nf_info_mp, nf_info);
                rte_exit(NF_NO_IDS, "There are no ids available for this NF\n");
        } else if(nf_info->status != NF_STARTING) {
                rte_mempool_put(nf_info_mp, nf_info);
                rte_exit(EXIT_FAILURE, "Error occurred during manager initialization\n");
        }
        RTE_LOG(INFO, APP, "Using Instance ID %d\n", nf_info->instance_id);
        RTE_LOG(INFO, APP, "Using Service ID %d\n", nf_info->service_id);

        /* Now, map rx and tx rings into client space */
        rx_ring = rte_ring_lookup(get_rx_queue_name(nf_info->instance_id));
        if (rx_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get RX ring - is server process running?\n");

        tx_ring = rte_ring_lookup(get_tx_queue_name(nf_info->instance_id));
        if (tx_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get TX ring - is server process running?\n");

        nf_msg_ring = rte_ring_lookup(get_msg_queue_name(nf_info->instance_id));
        if (nf_msg_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot get nf msg ring");


        /* Tell the manager we're ready to recieve packets */
        nf_info->status = NF_RUNNING;
        nf_info->lcore = rte_lcore_id(); //replace with current lcore
        nf_info->pid = getpid();
        #ifdef INTERRUPT_SEM
        init_shared_cpu_info(nf_info->instance_id);
        #endif

        RTE_LOG(INFO, APP, "Finished Process Init.\n");
        return retval_final;
}

double fetch_cpu_usage(void ) {
	static double perc = 0;
	struct timeval end, end_c;
	struct timeval diff, diff_c;
	struct rusage lusage;
	//printf("\n");
	int ret = getrusage(RUSAGE_SELF, &lusage);
	end = lusage.ru_utime;
	gettimeofday(&end_c, NULL);
	timersub(&end,&start, &diff);
	timersub(&end_c,&start_c, &diff_c);

	printf("End at: %ld.%lds ret = %d\n", end.tv_sec, end.tv_usec, ret);
	printf("Diff at: %ld.%lds\n", diff.tv_sec, diff.tv_usec);
	printf("Diff_C at: %ld.%lds\n", diff_c.tv_sec, diff_c.tv_usec);

	start = end;
	start_c = end_c;
	perc = (float) (diff.tv_sec * 1000000 + diff.tv_usec);
	perc = perc / ((float) (diff_c.tv_sec * 1000000 + diff_c.tv_usec));
	perc = perc *100;
	perc = (float) diff_c.tv_sec;
	printf("perc = %f\n", perc);
	return perc;
}

int
onvm_nflib_run(
        struct onvm_nf_info* info,
        pkt_handler handler)
{
        void *pkts[PKT_READ_SIZE];
        int pcount = 0;

        /* Don't allow conflicting NF modes */
        if (nf_mode == NF_MODE_RING) {
                return -1;
        }
        nf_mode = NF_MODE_SINGLE;

        printf("\nClient process %d handling packets\n", info->instance_id);
        printf("[Press Ctrl-C to quit ...]\n");

        /* Listen for ^C and docker stop so we can exit gracefully */
        signal(SIGINT, onvm_nflib_handle_signal);
        signal(SIGTERM, onvm_nflib_handle_signal);

        for (; keep_running;) {
                onvm_nflib_dequeue_packets(pkts, info, handler);
                onvm_nflib_dequeue_messages();
                pcount++;
                if(pcount > 40) {
                	info->cpu_usage = fetch_cpu_usage();
                	pcount = 0;
                }
        }

        // Stop and free
        onvm_nflib_cleanup();

        return 0;
}


int
onvm_nflib_return_pkt(struct rte_mbuf* pkt) {
        /* FIXME: should we get a batch of buffered packets and then enqueue? Can we keep stats? */
        if(unlikely(rte_ring_enqueue(tx_ring, pkt) == -ENOBUFS)) {
                rte_pktmbuf_free(pkt);
                tx_stats->tx_drop[nf_info->instance_id]++;
                return -ENOBUFS;
        }
        else tx_stats->tx_returned[nf_info->instance_id]++;
        return 0;
}

int
onvm_nflib_handle_msg(struct onvm_nf_msg *msg) {
        switch(msg->msg_type) {
        case MSG_STOP:
                RTE_LOG(INFO, APP, "Shutting down...\n");
                keep_running = 0;
                break;
        case MSG_NOOP:
        default:
                break;
        }

        return 0;
}

void
onvm_nflib_stop(void) {
        onvm_nflib_cleanup();
}


struct rte_ring *
onvm_nflib_get_tx_ring(__attribute__((__unused__)) struct onvm_nf_info* info) {
        /* Don't allow conflicting NF modes */
        if (nf_mode == NF_MODE_SINGLE) {
                return NULL;
        }

        /* We should return the tx_ring associated with the info struct */
        nf_mode = NF_MODE_RING;
        return tx_ring;
}


struct rte_ring *
onvm_nflib_get_rx_ring(__attribute__((__unused__)) struct onvm_nf_info* info) {
        /* Don't allow conflicting NF modes */
        if (nf_mode == NF_MODE_SINGLE) {
                return NULL;
        }

        /* We should return the rx_ring associated with the info struct */
        nf_mode = NF_MODE_RING;
        return rx_ring;
}


volatile struct client_tx_stats *
onvm_nflib_get_tx_stats(__attribute__((__unused__)) struct onvm_nf_info* info) {
        /* Don't allow conflicting NF modes */
        if (nf_mode == NF_MODE_SINGLE) {
                return NULL;
        }

        /* We should return the tx_stats associated with the info struct */
        nf_mode = NF_MODE_RING;
        return tx_stats;
}


/******************************Helper functions*******************************/


static inline void
onvm_nflib_dequeue_packets(void **pkts, struct onvm_nf_info *info, pkt_handler handler) {
        struct onvm_pkt_meta* meta;
        uint16_t i, j, nb_pkts;
        void *pktsTX[PKT_READ_SIZE];
        int tx_batch_size = 0;
        int ret_act;
        #ifdef INTERRUPT_SEM
        // To account NFs computation cost (sampled over SAMPLING_RATE packets)
        uint64_t start_tsc = 0, end_tsc = 0;
        #endif

	/* Dequeue all packets in ring up to max possible. */
	nb_pkts = rte_ring_dequeue_burst(rx_ring, pkts, PKT_READ_SIZE);

        if(unlikely(nb_pkts == 0)) {
                #ifdef INTERRUPT_SEM
                /* For now discard the special NF instance and put all NFs to wait
                if ((!ONVM_SPECIAL_NF) || (info->instance_id != 1)) {*/
                rte_atomic16_set(flag_p, 1);
                sem_wait(mutex);
                #endif
                return;
        }
        /* Give each packet to the user proccessing function */
        for (i = 0; i < nb_pkts; i++) {
                meta = onvm_get_pkt_meta((struct rte_mbuf*)pkts[i]);
                #ifdef INTERRUPT_SEM
                counter++;
                meta = onvm_get_pkt_meta((struct rte_mbuf*)pkts[i]);
                if (counter % SAMPLING_RATE == 0) {
                        start_tsc = rte_rdtsc();
                }
                #endif
                ret_act = (*handler)((struct rte_mbuf*)pkts[i], meta);
                #ifdef INTERRUPT_SEM
                if (counter % SAMPLING_RATE == 0) {
                        end_tsc = rte_rdtsc();
                        tx_stats->comp_cost[info->instance_id] = end_tsc - start_tsc;
                }
                #endif

                /* NF returns 0 to return packets or 1 to buffer */
                if(likely(ret_act == 0)) {
                        pktsTX[tx_batch_size++] = pkts[i];
                } else {
                        tx_stats->tx_buffer[info->instance_id]++;
                }
        }

        if (unlikely(tx_batch_size > 0 && rte_ring_enqueue_bulk(tx_ring, pktsTX, tx_batch_size) == -ENOBUFS)) {
                tx_stats->tx_drop[info->instance_id] += tx_batch_size;
                for (j = 0; j < tx_batch_size; j++) {
                        rte_pktmbuf_free(pktsTX[j]);
                }
        } else {
                tx_stats->tx[info->instance_id] += tx_batch_size;
        }
}

static inline void
onvm_nflib_dequeue_messages(void) {
        struct onvm_nf_msg *msg;

        // Check and see if this NF has any messages from the manager
        if (likely(rte_ring_count(nf_msg_ring) == 0)) {
                return;
        }
        msg = NULL;
        rte_ring_dequeue(nf_msg_ring, (void**)(&msg));
        onvm_nflib_handle_msg(msg);
        rte_mempool_put(nf_msg_pool, (void*)msg);
}


static struct onvm_nf_info *
onvm_nflib_info_init(const char *tag)
{
        void *mempool_data;
        struct onvm_nf_info *info;

        if (rte_mempool_get(nf_info_mp, &mempool_data) < 0) {
                rte_exit(EXIT_FAILURE, "Failed to get client info memory");
        }

        if (mempool_data == NULL) {
                rte_exit(EXIT_FAILURE, "Client Info struct not allocated");
        }

        info = (struct onvm_nf_info*) mempool_data;
        info->instance_id = initial_instance_id;
        info->service_id = service_id;
        info->status = NF_WAITING_FOR_ID;
        info->tag = tag;

        return info;
}


static void
onvm_nflib_usage(const char *progname) {
        printf("Usage: %s [EAL args] -- "
               "[-n <instance_id>]"
               "[-r <service_id>]\n\n", progname);
}


int
onvm_nflib_parse_args(int argc, char *argv[]) {
        const char *progname = argv[0];
        int c;

        opterr = 0;
        while ((c = getopt (argc, argv, "n:r:k:t:")) != -1) {
            RTE_LOG(INFO, APP, "Option name : %s:%c\n", __func__, c);
                switch (c) {
                case 'n':
                        initial_instance_id = (uint16_t) strtoul(optarg, NULL, 10);
                        break;
                case 'r':
                        service_id = (uint16_t) strtoul(optarg, NULL, 10);
                        // Service id 0 is reserved
                        if (service_id == 0) service_id = -1;
                        break;
                case '?':
                        onvm_nflib_usage(progname);
                        if (optopt == 'n' || optopt == 'l')
                                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                        else if (isprint(optopt))
                                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                        else
                                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
                        return -1;
                case 'k':
                        strncpy(client_name, optarg, strlen(optarg)+1);
                        client_name_extern = client_name;
                        RTE_LOG(INFO, APP, "Client name : %s:%s\n", __func__, client_name);
                        break;
				case 't':
						break;
                default:
                        return -1;
                }
        }

        if (service_id == (uint16_t)-1) {
                /* Service ID is required */
                fprintf(stderr, "You must provide a nonzero service ID with -r\n");
                return -1;
        }
        return optind;
}


static void
onvm_nflib_handle_signal(int sig)
{
        if (sig == SIGINT || sig == SIGTERM) {
                keep_running = 0;
                #ifdef INTERRUPT_SEM
                if ((mutex) && (rte_atomic16_read(flag_p) ==1)) {
                        rte_atomic16_set(flag_p, 0);
                        sem_post(mutex);
                }
                #endif
        }
        /* TODO: Main thread for INTERRUPT_SEM case: Must additionally relinquish SEM, SHM */
}

static void
onvm_nflib_cleanup(void) {
        struct onvm_nf_msg *shutdown_msg;
        nf_info->status = NF_STOPPED;

        /* Put this NF's info struct back into queue for manager to ack shutdown */
        if (mgr_msg_queue == NULL) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_exit(EXIT_FAILURE, "Cannot get nf_info ring for shutdown");
        }
        if (rte_mempool_get(nf_msg_pool, (void**)(&shutdown_msg)) != 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_exit(EXIT_FAILURE, "Cannot create shutdown msg");
        }

        shutdown_msg->msg_type = MSG_NF_STOPPING;
        shutdown_msg->msg_data = nf_info;

        if (rte_ring_enqueue(mgr_msg_queue, shutdown_msg) < 0) {
                rte_mempool_put(nf_info_mp, nf_info); // give back mermory
                rte_mempool_put(nf_msg_pool, shutdown_msg);
                rte_exit(EXIT_FAILURE, "Cannot send nf_info to manager for shutdown");
        }
}

#ifdef INTERRUPT_SEM
static void
init_shared_cpu_info(uint16_t instance_id) {
        const char *sem_name;
        int shmid;
        key_t key;
        char *shm;

        sem_name = get_sem_name(instance_id);
        fprintf(stderr, "sem_name=%s for client %d\n", sem_name, instance_id);
        mutex = sem_open(sem_name, 0, 0666, 0);
        if (mutex == SEM_FAILED) {
                perror("Unable to execute semaphore");
                fprintf(stderr, "unable to execute semphore for client %d\n", instance_id);
                sem_close(mutex);
                exit(1);
        }

        /* get flag which is shared by server */
        key = get_rx_shmkey(instance_id);
        if ((shmid = shmget(key, SHMSZ, 0666)) < 0) {
                perror("shmget");
                fprintf(stderr, "unable to Locate the segment for client %d\n", instance_id);
                exit(1);
        }

        if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
                fprintf(stderr, "can not attach the shared segment to the client space for client %d\n", instance_id);
                exit(1);
        }

        flag_p = (rte_atomic16_t *)shm;
}
#endif
