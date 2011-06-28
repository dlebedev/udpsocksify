/**************************************************************************************************
 *  Description:  Framework for capturing packets from NFQUEUE for processing. 
 *
 *	Before you run this you need to direct packets to the NFQUEUE queue, for example :
 *		  # iptables -A PREROUTING -p udp -j NFQUEUE --queue-num 10
 *
 *		  These will direct all udp packets respectively.  Other iptable filters
 *		  can be crafted to redirect specfic packets to the queue.  If you dont redirect any
 *		  packets to the queue your program won't see any packets.
 *
 *  to remove the filter: # iptables --flush
 *
 *  Must execute as root: # ./udps -q num
 **************************************************************************************************/

#include "udps.h"
#include <linux/netfilter_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
//#include <netdb.h>		// for getservbyname()

// constantsq 10// ---------
#define VERSION_MAJOR 0
#define VERSION_MINOR 1

#define MAX_PKTSIZE 65535
#define MAX_QUEUE_LEN 65535

#define IPV4 4

#define NUM_THREADS 4

// global variables
// ---------

struct queues_t {
    struct nfq_q_handle *qh;
    struct nfq_handle *nfqh;
    struct nfnl_handle *nh;
    struct queues_t *next;
} *queues = NULL;

char *conf_file = NULL;

// prototypes
// ----------
short int netlink_loop(unsigned short int queuenum);
static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
void print_options(void);

// function for thread 
// --------------------
void *tcap_packet_function(void *threadarg) {
    netlink_loop((unsigned long int)threadarg);
    pthread_exit(NULL);
}

void *reread_config(void* unused) {
    FILE *fd = NULL;
    
    if ((fd = fopen(conf_file, "r")) != NULL) {
        reread_configuration_file(fd);
        fclose(fd);
    }
    pthread_mutex_unlock(&mutexconf);
    
    pthread_exit(NULL);
}

void *cleaning_connections(void* unused) {
    do_timeout();
    pthread_exit(NULL);
}

void garbage_collect() {
    struct udps_config_t *conf;
    struct usock_t *usock;
    struct queues_t *queue;
    void *tmp;
    
    /* free all allocated memory */
    conf = default_config;
    while (conf) {
        tmp = (void *)conf;
        conf = conf->next;
    }

    usock = default_usock;
    while (usock) {
        close(usock->sk);
        tmp = (void *)usock;
        remove_connections(usock, NULL);
        usock = usock->next;
        free(tmp);
    }
    
    queue = queues;
    while (queue) {
        //nfq_destroy_queue(queue->qh);
        nfq_close(queue->nfqh);
        //queue = queue->next;
        tmp = (void *)queue;
        queue = queue->next;
        free(tmp);
    }
}

/* Ctrl+C will get you here */
void sig_handler(int signum) {
    int ret;
    pthread_t thread_id;
    
    switch (signum) {
        case SIGUSR1:
            /* Rereading config */
            if (pthread_mutex_trylock(&mutexconf) == 0)
                ret = pthread_create(&thread_id, NULL, &reread_config, NULL);
            break;
        default:
            /* Freeing memory and exit */
            pthread_mutex_lock(&mutexconf);
            pthread_mutex_lock(&mutexusock);
            garbage_collect();
            /* Wait for unlocking mutex and destroy them */
            pthread_mutex_unlock(&mutexusock);
            pthread_mutex_destroy(&mutexusock);
            pthread_mutex_unlock(&mutexconf);
            pthread_mutex_destroy(&mutexconf);
            exit(ERR);
    }
}

void setup_signal_handlers() {
#ifdef __linux__
    struct sigaction sa;
    
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = &sig_handler;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    
    /* required for non-blocking sockets */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
#endif
}

// main function
// -------------
int main(int argc, char **argv) {
    int done = 0, ret = 0;
    int daemonized = 0;		// for background program
    FILE *fd = NULL;
    struct udps_config_t *config = NULL;
    pthread_t threads[NUM_THREADS];
  
    // check parameters
    // ----------------
    if (argc < 1) {
        print_options();
        exit(ERR);
    }
  
    // check root user ?
    // -----------------
    if (getuid() != 0 || geteuid() != 0) {
        error(ERR, 0, "udps version %d.%d\nCopyright (c) 2011  delete\n\n" \
              "This program can be run only by the system administrator\n", VERSION_MAJOR, VERSION_MINOR);
    }
    
    pthread_mutex_init(&mutexconf, NULL);
    pthread_mutex_init(&mutexusock, NULL);
#ifdef __linux__
    setup_signal_handlers();
#endif

    // parse command line
    // ------------------

    while (!done) {		//scan command line options
        ret = getopt(argc, argv, ":hc:D");		
        switch (ret) {		
            case -1 :
                done = 1;
                break;
            case 'h':
                print_options();
                exit(OK);
            case 'c':
                conf_file = strdup(optarg);
                break;			
            case 'D':
                daemonized = 1;
                break;
            case '?':	// unknown option
                error(ERR, 0, "Invalid option or missing parameter, use packet_engine -h for help\n");
        }
    }
    if (conf_file == NULL)
        conf_file = strdup("/opt/udps/udps.conf");
  
    // initialization
    // --------------
    if ((fd = fopen(conf_file, "r")) == NULL)
        error(ERR, 0, "[!] Could not open the configuration file");

    /*parse_configuration_file(configuration_fd);*/
    if (parse_configuration_file(fd, &config))
        exit(ERR);
    
    if (fd)
        fclose(fd);
    
    default_config = config;
    
    if ((default_config->nat_ip == 0) || (default_config->connect_ip == 0)
        || (default_config->queue_internal <= 0) || (default_config->queue_internal2 <= 0)
        || (default_config->queue_external <= 0))
        error(ERR, 0, "[!] Configuration file does not filled correctly\n");
    
    printf("Initialization...OK\n");
  
    // check if program run in background ?
    // ------------------------------------
    if (daemonized) {
        switch (fork()) {
            case 0:			/* child */
                setsid();
                fd = freopen("/dev/null", "w", stdout);	/* redirect std output */
                fd = freopen("/dev/null", "r", stdin);	/* redirect std input */
                fd = freopen("/dev/null", "w", stderr);	/* redirect std error */
                break;
            case -1:		/* error */
                error(ERR, 0, "Fork error, the program cannot run in background\n");
            default:		/* parent */
                exit(OK);
        }
    }
  
    // begin with netfilter
    // -------------------------------------
    ret = pthread_create(&threads[0], NULL, &tcap_packet_function, (void *)default_config->queue_internal);
    if (ret)
        error(ERR, 0, "ERROR: return code from pthread_create() is %d\n", ret);
    
    ret = pthread_create(&threads[1], NULL, &tcap_packet_function, (void *)default_config->queue_internal2);
    if (ret)
        error(ERR, 0, "ERROR: return code from pthread_create() is %d\n", ret);
    
    ret = pthread_create(&threads[2], NULL, &tcap_packet_function, (void *)default_config->queue_external);
    if (ret)
        error(ERR, 0, "ERROR: return code from pthread_create() is %d\n", ret);
    
    /* thread for cleaning connections */
    ret = pthread_create(&threads[3], NULL, &cleaning_connections, NULL);
    if (ret)
        error(ERR, 0, "ERROR: return code from pthread_create() is %d\n", ret);
    
    pthread_exit(NULL);
}

// loop to process a received packet at the queue
// ----------------------------------------------
short int netlink_loop(unsigned short int queuenum) {
	int fd, rv;
	char buf[MAX_PKTSIZE];
	struct queues_t *queue;
    
	pthread_mutex_lock(&mutexusock);
	queue = malloc(sizeof(struct queues_t));
	// opening library handle
	queue->nfqh = nfq_open();
	if (!queue->nfqh)
		error(ERR, 0, "Error during nfq_open()\n");

	// unbinding existing nf_queue handler for AF_INET (if any)
	// an error with Kernel 2.6.23 or above --> commented 2 lines 
	if (nfq_unbind_pf(queue->nfqh, AF_INET) < 0)
		error(ERR, 0, "Error during nfq_unbind_pf()\n");
	
	// binds the given queue connection handle to process packets.
	if (nfq_bind_pf(queue->nfqh, AF_INET) < 0)
		error(ERR, 0, "Error during nfq_bind_pf()\n");
	printf("NFQUEUE: binding to queue '%hd'\n", queuenum);
	
	// create queue
	queue->qh = nfq_create_queue(queue->nfqh,  queuenum, &nfqueue_cb, NULL);
	if (!queue->qh)
		error(ERR, 0, "Error during nfq_create_queue()\n");
	
	// sets the amount of data to be copied to userspace for each packet queued
	// to the given queue.
	if (nfq_set_mode(queue->qh, NFQNL_COPY_PACKET, MAX_PKTSIZE) < 0)
		error(ERR, 0, "Can't set packet_copy mode\n");
    
	// Set kernel queue maximum length parameter
	if (nfq_set_queue_maxlen(queue->qh, MAX_QUEUE_LEN) < 0)
		error(ERR, 0, "Can't set max len of queue\n");
    
	// returns the netlink handle associated with the given queue connection handle.
	// Possibly useful if you wish to perform other netlink communication
	// directly after opening a queue without opening a new netlink connection to do so
	queue->nh = nfq_nfnlh(queue->nfqh);
    
	queue->next = queues;
	queues = queue;
	pthread_mutex_unlock(&mutexusock);
    
	// returns a file descriptor for the netlink connection associated with the
	// given queue connection handle.  The file descriptor can then be used for
	// receiving the queued packets for processing.
	fd = nfnl_fd(queue->nh);
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		// triggers an associated callback for the given packet received from the queue.
		// Packets can be read from the queue using nfq_fd() and recv().
		nfq_handle_packet(queue->nfqh, buf, rv);
        memset(buf, 0x0, sizeof(buf));
        for (;;) {
            if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
                nfq_handle_packet(queue->nfqh, buf, rv);
                memset(buf, 0x0, sizeof(buf));
                continue;
            }
            /* if the computer is slower than the network the buffer
             * may fill up. Depending on the application, this error
             * may be ignored */
            if (errno == ENOBUFS) {
                printf("packet lost!!\n");
                continue;
            }
            printf("NFQUEUE: recv failed: errno=%d (%s)\n", errno, strerror(errno));
        }
	}
	// unbinding before exit
	printf("NFQUEUE: unbinding from queue '%hd'\n", queuenum);
	nfq_destroy_queue(queue->qh);
	nfq_close(queue->nfqh);
	return OK;
}

struct udps_config_t *find_config_by_ip(uint32_t client_ip) {
    struct udps_config_t *config;
    
    config = default_config;
    while (config) {
        if (config->client_ip == client_ip)
            return config;
        config = config->next;
    }
    return default_config;
}

struct conn_t *connections_revise(u_int32_t src_ip, u_int16_t srcport,
                                  u_int32_t dst_ip, u_int16_t dstport,
                                  u_int32_t sk_ip, u_int16_t skport, u_int8_t inout) {
    struct udps_config_t *config = NULL;
    struct usock_t *usock = NULL;
    struct conn_t *conn = NULL;
    
    pthread_mutex_lock(&mutexusock);
    if (inout) {
        /* Incoming connection */
        usock = find_connection(sk_ip, skport, src_ip, srcport, inout);
    }
    else {
        /* Outcoming connection */
        config = find_config_by_ip(src_ip);
        usock = find_connection(config->connect_ip, config->connect_port, config->nat_ip, srcport, inout);
    }
    
    if (usock) {
        conn = usock->conn;
        while (conn) {
            if ((conn->dst_ip == dst_ip) && (conn->dstport == dstport)) {
                conn->timestamp = time(NULL);
                pthread_mutex_unlock(&mutexusock);
                return conn;
            }
            conn = conn->next;
        }
    }
    
    if (inout) {
        /* Incoming packet but no matching connections */
        pthread_mutex_unlock(&mutexusock);
        return NULL;
    }
    
    /* Only for outcoming packets                     */
    /* If control TCP connection already established, */
    /* we don't need to find config                   */
    /* Just create new conn in founded usock          */
    if (!usock) {
        pthread_mutex_unlock(&mutexusock);
        
        usock = malloc(sizeof(struct usock_t));
        usock->sk = 0;
        usock->conn = NULL;
        usock->connect_ip = config->connect_ip;
        usock->connect_port = config->connect_port;
        usock->src_port = srcport;
        usock->nat_ip = config->nat_ip;
        
        if (create_connection(config, srcport, usock) < 0) {
    	    printf("%s\n", strerror(errno));
            free(usock);
            return NULL; /* Error while appempt to create connection to socks-server */
        }
        printf("connection created\n");
        
        pthread_mutex_lock(&mutexusock);
        if (default_usock) {
            usock->next = default_usock->next;
            default_usock->next = usock;
        }
        else {
            default_usock = usock;
            usock->next = NULL;
        }
    }
    
    /* Add connection in tree */
    conn = malloc(sizeof(struct conn_t));
    
    conn->src_ip = src_ip;
    
    conn->dst_ip = dst_ip;
    conn->dstport = dstport;
    
    conn->usock = usock;
    conn->timestamp = time(NULL);
    conn->next = usock->conn;
    usock->conn = conn;
    pthread_mutex_unlock(&mutexusock);
    
    return conn;
}

// socksify and desocksify packets
// ----------------------------------------
unsigned char *process_packet(unsigned char *pkt, int *len, u_int8_t hook) {
    struct conn_t *conn = NULL;
    struct ip *iph;
    struct udphdr *udph;
    unsigned char *data, *new_data;
    unsigned char *new_pkt = NULL;
    u_int32_t *dst_ip;
    u_int16_t *dstport;
    u_int8_t in_out;
    struct udps_config_t *config;
    
    /* It's a trick to avoid problems with routings
     *  We only change source ip to nat-ip */
    if (hook == NF_IP_POST_ROUTING) {
        new_pkt = malloc(*len);
        memcpy(new_pkt, pkt, *len);
        iph = (struct ip *)new_pkt;
        udph = (struct udphdr *)(new_pkt + sizeof(struct ip));
        
        config = find_config_by_ip(iph->ip_src.s_addr);
        
        iph->ip_src.s_addr = config->nat_ip;
        udp_checksum(iph);
        ip_checksum(iph);
        
        return new_pkt;
    }
    
    iph = (struct ip *)pkt;
    udph = (struct udphdr *)(pkt + sizeof(struct ip));
    
    in_out = 0;
    config = default_config;
    while (!in_out && config) {
        if (iph->ip_dst.s_addr == config->nat_ip)
            in_out = 1;
        config = config->next;
    }
    
    if (in_out) {
        /* incoming packet - to client
         * Desocksify packet:
         *
         * Change src ip to real from socks5
         * and unpack udp */
        if (*len > sizeof(struct ip) + sizeof(struct udphdr) + SOCKS_HEADER_UDP_SIZE_V4) { /* Is this correct udp-packet? */
            data = (unsigned char *)(pkt + sizeof(struct ip) + sizeof(struct udphdr));
            dst_ip = (u_int32_t *)(data + sizeof(u_int32_t));
            dstport = (u_int16_t *)(data + sizeof(u_int32_t) * 2);
            conn = connections_revise(iph->ip_dst.s_addr, udph->uh_dport, *dst_ip, *dstport, iph->ip_src.s_addr, udph->uh_sport, 1);
            if (conn == NULL) 
                return NULL;
                
            *len = *len - SOCKS_HEADER_UDP_SIZE_V4;
            new_pkt = malloc(*len);
                
            memcpy(new_pkt, pkt, sizeof(struct ip) + sizeof(struct udphdr));
            new_data = (unsigned char *)(new_pkt + sizeof(struct ip) + sizeof(struct udphdr));
            memcpy(new_data, &data[SOCKS_HEADER_UDP_SIZE_V4], *len - sizeof(struct ip) - sizeof(struct udphdr));
                
            iph = (struct ip *)new_pkt;
            udph = (struct udphdr *)(new_pkt + sizeof(struct ip));
                
            iph->ip_src.s_addr = conn->dst_ip;
            iph->ip_dst.s_addr = conn->src_ip; // little bit an ip-spoofing for udp
            iph->ip_len = htons(ntohs(iph->ip_len) - SOCKS_HEADER_UDP_SIZE_V4);
            udph->uh_sport = conn->dstport;
            udph->uh_ulen = htons(ntohs(udph->uh_ulen) - SOCKS_HEADER_UDP_SIZE_V4); /* trancate udp data */
                
            /* Calculate checksums... */
            udp_checksum(iph);
            ip_checksum(iph);
        }
    }
    else {
        /* outcoming packet - to socks5 server
         * Socksify packet
         *
         * Change dst ip from real to socks5
         * and pack udp */
        if (*len > sizeof(struct ip) + sizeof(struct udphdr)) { /* Is this correct udp-packet? */
            conn = connections_revise(iph->ip_src.s_addr, udph->uh_sport, iph->ip_dst.s_addr, udph->uh_dport, 0, 0, 0);
            if (conn == NULL) /* Something wrong... */
                return NULL;
            
            *len = *len + SOCKS_HEADER_UDP_SIZE_V4;
            new_pkt = malloc(*len);
            
            memcpy(new_pkt, pkt, sizeof(struct ip) + sizeof(struct udphdr));
            data = (unsigned char *)(pkt + sizeof(struct ip) + sizeof(struct udphdr));
            new_data = (unsigned char *)(new_pkt + sizeof(struct ip) + sizeof(struct udphdr));
            
            new_data[0] = 0x0;
            new_data[1] = 0x0;
            new_data[2] = 0x0;
            new_data[3] = 0x1;
            memcpy(&new_data[4], &conn->dst_ip, sizeof(uint32_t));
            memcpy(&new_data[8], &conn->dstport, sizeof(uint16_t));
            memcpy(&new_data[10], data, *len - sizeof(struct ip) - sizeof(struct udphdr) - SOCKS_HEADER_UDP_SIZE_V4);
            
            iph = (struct ip *)new_pkt;
            udph = (struct udphdr *)((long *)iph + iph->ip_hl);
            
            iph->ip_dst.s_addr = conn->usock->sk_ip;
            iph->ip_len = htons(ntohs(iph->ip_len) + SOCKS_HEADER_UDP_SIZE_V4);
            udph->uh_dport = conn->usock->sk_port;
            udph->uh_ulen = htons(ntohs(udph->uh_ulen) + SOCKS_HEADER_UDP_SIZE_V4); /* trancate udp data */
            
            /* Calculate checksums... */
            udp_checksum(iph);
            ip_checksum(iph);
        }
        /*else
          printf("len is too small\n");*/
    }
    return new_pkt;
}

// function callback for packet processing
// ---------------------------------------
static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                      struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    int id_protocol = 0, id = 0, len = 0;
    unsigned char *full_packet; // get data of packet (payload)
    unsigned char *new_packet = NULL;
    
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        len = nfq_get_payload(nfa, &full_packet);
        id = ntohl(ph->packet_id);
        id_protocol = identify_ip_protocol(full_packet);
        if (id_protocol == IPPROTO_UDP) { /* Only UDP packets */
            printf("Packet from %s:%d", get_src_ip_str(full_packet), get_udp_src_port(full_packet));
            printf(" to %s:%d\n", get_dst_ip_str(full_packet), get_tcp_dst_port(full_packet));
            /* Process packet... */
            new_packet = process_packet(full_packet, &len, ph->hook);
        }
        // let the packet continue on.  NF_ACCEPT will pass the packet
        // -----------------------------------------------------------
        if (new_packet) {
            nfq_set_verdict(qh, id, NF_ACCEPT, len, new_packet);
            free(new_packet);
        }
        else
            nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    } else {
        printf("NFQUEUE: can't get msg packet header.\n");
        return ERR;		// from nfqueue source: 0 = ok, >0 = soft error, <0 hard error
    }

    return OK;
}

/*
 * this function displays usages of the program
 */
void print_options(void) {
    printf("udps %d.%d by delete\n", VERSION_MAJOR, VERSION_MINOR);
    printf("Copyright (C) 2011\n");
    printf("This program comes with ABSOLUTELY NO WARRANTY.\n");
    printf("This is free software, and you are welcome to redistribute it\n");
    printf("under certain conditions.\n");
    printf("\nSyntax: udps [ -h ] [ -q queue-num] [ -D ]\n");
    printf("  -h\t\t- display this help and exit\n");
    printf("  -c <path to config file>\t- specify an alternative config file\n");
    printf("  -D\t\t- run this program in background.\n\n");
}
