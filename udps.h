#ifndef UDPS_H_
#define UDPS_H_

#define __USE_BSD
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <error.h>
#include <errno.h>
#include <pthread.h>

// Prototypes
int identify_ip_protocol(unsigned char *payload);
char *get_src_ip_str(unsigned char *payload);
char *get_dst_ip_str(unsigned char *payload);
int get_tcp_src_port(unsigned char *payload);
int get_tcp_dst_port(unsigned char *payload);
int get_udp_src_port(unsigned char *payload);
int get_udp_dst_port(unsigned char *payload);

void ip_checksum(struct ip *ip);
void tcp_checksum(struct ip *ip);
void udp_checksum(struct ip *ip);
int sum_words(u_int16_t *buf, int nwords);

pthread_mutex_t mutexconf;
pthread_mutex_t mutexusock;

#define MAX_CONFIGURATION_LINES 65535
#define MAX_CONFIGURATION_LINE_LEN 2048
#define MAX_CONFIGURATION_STRING 1024

#define ERR -1
#define OK 0

#define YES 1
#define NO 0

#define ON 1
#define OFF 0

#define IPV4 4
#define IPV6 6

#define MAX_UNAME 255

#define SOCKS_VERSION 5

#define SOCKS_HEADER_UDP_SIZE_V4  10

/**
 * The implemented method for SOCKS5
 */
enum socks5_method {
    NO_AUTH_REQ = 0x00,	/* No authentication required	           */
    GSSAPI = 0x01,	    /* GSSAPI			                       */
    USER_PWD = 0x02,	/* Username and password	               */
                        /* from 0x03 to 0x7F, are Assigned by IANA */
                        /* from 0x80 to 0xFE are Reserved	       */
    NAM = 0xFF		    /* Not Acceptable method	               */
};

#define SOCKS5_METHOD_IMPLEMENTED  0x02		/* NO_AUTH_REQ, USER_PWD */
#define SOCKS5_METHODS 255

/* socks5 (RFC-1928) */
#define LEN_SOCKS5_METHODS 2

enum socks5_command {
    /* Connect request */
    CMD_AUTH = 0x01,
    UDP_ASSOCIATE = 0x03,
    RSV = 0x00,
    ATYP_V4 = 0x01,	/* IPv4 Address */
    ATYP_DN = 0x03,	/* Domain Name Address */
    ATYP_V6 = 0x04,	/* IPv6 Address */
};

struct socks5_methods {
    uint8_t ver;
    uint8_t nmethods;
    uint8_t methods[SOCKS5_METHOD_IMPLEMENTED];
};

#define LEN_SOCKS5_REQ 10

struct socks5_req {
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
    uint32_t dst_ip;
    uint16_t dstport;
};

/* RFC-1929 (Socks5 Authentication) */
#define LEN_SOCKS5_AUTH_REQ 3

struct socks5_auth_req {
	uint8_t ver;
	uint8_t ulen;
	uint8_t uname_plen_password[2 * MAX_UNAME + 1];
};

#define SOCKS5_AUTH_REPLY 2
#define SOCKS5_UDP_REPLY 10

struct socks5_auth_reply {
	uint8_t ver;
	uint8_t status;
};

struct conn_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dstport;
    time_t timestamp;
    struct usock_t *usock;
    struct conn_t *next;
};

struct usock_t {
    int sk;
    uint32_t connect_ip;
    uint16_t connect_port;
    uint32_t sk_ip;
    uint16_t sk_port;
    uint32_t nat_ip;
    uint16_t src_port;
    struct conn_t *conn;
    struct usock_t *next;
} *default_usock;

struct udps_config_t {
	/* Credential for socks5 */
    char *name;
    uint32_t queue_internal;
    uint32_t queue_internal2;
    uint32_t queue_external;
    uint32_t client_ip;
    uint32_t connect_ip;
    uint16_t connect_port;
    uint32_t nat_ip;
    uint8_t auth_method; /* 0 - no auth, 1 - user/password auth */
    char *user;
    char *passwd;
    struct udps_config_t *next;
} *default_config;

int parse_configuration_file(FILE *configuration_fd, struct udps_config_t **config_struct);
int reread_configuration_file(FILE *conf_fd);
void remove_connections(struct usock_t *usock, struct udps_config_t *conf);
struct usock_t *find_connection(uint32_t sk_ip, uint16_t sk_port, uint32_t nat_ip, uint16_t src_port, uint8_t inout);
void release_config(struct udps_config_t *conf);
void do_timeout(void);
int create_connection(struct udps_config_t *config, const u_int16_t srcport, struct usock_t *usock);

#endif /*UDPS_H_*/
