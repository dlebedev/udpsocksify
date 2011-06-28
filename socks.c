#include "udps.h"
#include <fcntl.h>
#include <poll.h>

static uint8_t socks5_method_implemented[] = {NO_AUTH_REQ, USER_PWD};

void do_timeout(void) {
    time_t t;
    struct usock_t *prev_usock = NULL, *usock = default_usock;
    struct conn_t *prev_conn = NULL, *conn;
    int cnt;
    
    while (1) {
        pthread_mutex_lock(&mutexusock);
        t = time(NULL);
        cnt = 0;
        printf("DEBUG: do_timeout() going to clean\n");
        usock = default_usock;
        prev_usock = NULL;
        while (usock) {
            conn = usock->conn;
            prev_conn = NULL;
            while (conn) {
                if ((t - conn->timestamp) > 30) {
                    /* remove old connections */
                    if (prev_conn) {
                        prev_conn->next = conn->next;
                        free(conn);
                        conn = prev_conn->next;
                    }
                    else {
                        /* first conn in usock */
                        usock->conn = conn->next;
                        free(conn);
                        conn = usock->conn;
                    }
                    continue;
                }
                prev_conn = conn;
                conn = conn->next;
            }
            if (!usock->conn) {
                /* unused socket -> remove him */
                shutdown(usock->sk, SHUT_RDWR);
                close(usock->sk);
                if (prev_usock) {
                    prev_usock->next = usock->next;
                    free(usock);
                    usock = prev_usock->next;
                }
                else {
                    /* prev_usock is NULL -> need move default_usock */
                    default_usock = usock->next;
                    free(usock);
                    usock = default_usock;
                }
                    printf("DEBUG: removed usock\n");
                continue;
            }
            else
                cnt++;
            prev_usock = usock;
            usock = usock->next;
        }
        printf("DEBUG: connections: %d\n", cnt);
        pthread_mutex_unlock(&mutexusock);
        sleep(10);
    }
}

int min(int a, int b) {
    return ((a < b) ? a : b);
}

int sendTCP(int sock, int lenght, void *sen) {
    fd_set set;
    struct timeval timeout;
    int ret;
    
    /* Set time limit. */
    timeout.tv_sec = 4;
    timeout.tv_usec = 0;
    
    while (1) {
        FD_ZERO(&set);
        FD_SET(sock, &set);
        ret = select(sock + 1, NULL, &set, NULL, &timeout);
        if (ret == 0) {
            printf("DEBUG: select return 0 in sendTCP()\n");
            return -2;
        }
        if (ret < 0)
            return ERR;
        if (FD_ISSET(sock, &set))
            return send(sock, (void *)sen, lenght, MSG_NOSIGNAL);
        continue;
    }
    return ERR;
}

int recvTCP(int sock, int rrlen, void *response) {
    fd_set set;
    struct timeval timeout;
    int ret;
    
    /* Set time limit. */
    timeout.tv_sec = 4;
    timeout.tv_usec = 0;
    
    while (1) {
        FD_ZERO(&set);
        FD_SET(sock, &set);
        ret = select(sock + 1, &set, NULL, NULL, &timeout);
        if (ret == 0) {
            printf("DEBUG: select return 0 in recvTCP()\n");
            return -2;
        }
        if (ret < 0)
            return ERR;
        if (FD_ISSET(sock, &set))
            return recv(sock, (void *)response, rrlen, MSG_DONTWAIT);
        continue;
    }
    
    return ERR;
}

int create_connection(struct udps_config_t *config, const u_int16_t srcport, struct usock_t *usock) {
    struct sockaddr_in socks5_server;
    void *socks_req = NULL;
    void *response = NULL;
    int i, len, res;
    fd_set set;
    time_t t;
    
    if ((usock->sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
	printf("socket() failure\n");
        return ERR;
    }
    fcntl(usock->sk, F_SETFL, O_NONBLOCK);
    memset(&socks5_server, 0, sizeof(struct sockaddr_in));  /* Clear struct */
    socks5_server.sin_family = AF_INET;                     /* Internet/IP  */
    socks5_server.sin_addr.s_addr = usock->connect_ip;      /* IP address   */
    socks5_server.sin_port = htons(usock->connect_port);    /* Server port  */
    /* Establish connection */
    t = time(NULL);
    printf("DEBUG: new connection at time %s\n", ctime(&t));
    if (connect(usock->sk, (struct sockaddr *)&socks5_server, sizeof(socks5_server)) < 0) {
        while (1) {
            if (errno == EINPROGRESS) {
                FD_ZERO(&set);
                FD_SET(usock->sk, &set);
                if (select(usock->sk + 1, NULL, &set, NULL, NULL) <= 0)
                    break;
                if (FD_ISSET(usock->sk, &set))
                    break;
                continue;
	    }
            else {
        	printf("connect() failure\n");
                goto SOCK_ERR;
            }
        }
    }
        
    /* Send authentification methods supported */
    socks_req = malloc(sizeof(struct socks5_methods));
    memset(socks_req, 0, sizeof(struct socks5_methods));
    ((struct socks5_methods *)socks_req)->nmethods = 0;
    ((struct socks5_methods *)socks_req)->ver = SOCKS_VERSION;
    
    for (i=0; i < SOCKS5_METHOD_IMPLEMENTED; i++) {
        ((struct socks5_methods *)socks_req)->methods[i] = socks5_method_implemented[i];
        ((struct socks5_methods *)socks_req)->nmethods++;
    }
    
    len = LEN_SOCKS5_METHODS + SOCKS5_METHOD_IMPLEMENTED;
    res = sendTCP(usock->sk, len, socks_req);
    if (res <= 0) {
        t = time(NULL);
        printf("DEBUG: sendTCP() failure at %s\n", ctime(&t));
        if (res == 0)
            printf("closed connection\n");
        if (res == -2)
            printf("select() timed out\n");
        free(socks_req);
        goto SOCK_ERR;
    }
    
    free(socks_req);
    
    response = malloc(SOCKS5_AUTH_REPLY);
    memset(response, 0, SOCKS5_AUTH_REPLY);
    
    res = recvTCP(usock->sk, SOCKS5_AUTH_REPLY, response);
    if (res <= 0) {
        t = time(NULL);
        printf("DEBUG: recvTCP() failure at %s\n", ctime(&t));
        if (res == 0)
            printf("closed connection\n");
        if (res == -2)
            printf("select() timed out\n");
        free(response);
        goto SOCK_ERR;
    }
    
    switch (((struct socks5_auth_reply *)response)->status) {
        case NO_AUTH_REQ:
            /* ok, now send directly the request */
            break;
            
        case USER_PWD:
            /* creating request for authentication */
            
            printf("Authorization required!\n");
            
            socks_req = malloc(sizeof(struct socks5_auth_req));
            memset(socks_req, 0, sizeof(struct socks5_auth_req));
            
            ((struct socks5_auth_req *)socks_req)->ver = CMD_AUTH;
            
            /* Copy user_name */
            ((struct socks5_auth_req *) socks_req)->ulen = min(MAX_UNAME, strlen(config->user));
            memset(((struct socks5_auth_req *) socks_req)->uname_plen_password, 0, 2 * MAX_UNAME + 1);
            memcpy(((struct socks5_auth_req *) socks_req)->uname_plen_password,
                   config->user, ((struct socks5_auth_req *) socks_req)->ulen);
            
            /* Copy password */
            ((struct socks5_auth_req *)socks_req)->uname_plen_password[((struct socks5_auth_req *)socks_req)->ulen] = min(MAX_UNAME, strlen(config->passwd));
            memcpy(&(((struct socks5_auth_req *)socks_req)->uname_plen_password[((struct socks5_auth_req *)socks_req)->ulen + 1]),
                   config->passwd, ((struct socks5_auth_req *)socks_req)->uname_plen_password[((struct socks5_auth_req *)socks_req)->ulen]);
            
            len = LEN_SOCKS5_AUTH_REQ + ((struct socks5_auth_req *)socks_req)->ulen +
                  ((struct socks5_auth_req *)socks_req)->uname_plen_password[((struct socks5_auth_req *)socks_req)->ulen];
            
            if (sendTCP(usock->sk, len, socks_req) <= 0) {
                free(socks_req);
                goto SOCK_ERR;
            }
            
            free(socks_req);
            
            response = malloc(SOCKS5_AUTH_REPLY);
            memset(response, 0, SOCKS5_AUTH_REPLY);
            
            if (recvTCP(usock->sk, SOCKS5_AUTH_REPLY, response) <= 0) {
                free(response);
                goto SOCK_ERR;
            }
            
            if (((struct socks5_auth_reply *)response)->status != 0) {
                printf("Authorization on socks5 server failed!\n");
                goto SOCK_ERR;
            }
            break;
        default:
    	    printf("wrong auth method\n");
            goto SOCK_ERR; /* Something wrong */
    } /* switch */
    /* auth step is fine, now can send request */ 
    
    socks_req = malloc(sizeof(struct socks5_req));
    memset(socks_req, 0, sizeof(struct socks5_req));
    
    ((struct socks5_req *)socks_req)->ver = SOCKS_VERSION;
    ((struct socks5_req *)socks_req)->cmd = UDP_ASSOCIATE;
    ((struct socks5_req *)socks_req)->rsv = RSV;
    
    ((struct socks5_req *)socks_req)->atyp = ATYP_V4;
    /* Formerly we want send data from same ip that control connection */
    //((struct socks5_req *)socks_req)->dst_ip = inet_addr("0.0.0.0");
    ((struct socks5_req *)socks_req)->dst_ip = config->nat_ip;
    ((struct socks5_req *)socks_req)->dstport = srcport;
    
    /* send connection request */
    res = sendTCP(usock->sk, LEN_SOCKS5_REQ, socks_req);
    if (res <= 0) {
        t = time(NULL);
        printf("DEBUG: sendTCP(2) failure at %s\n", ctime(&t));
        if (res == 0)
            printf("closed connection\n");
        if (res == -2)
            printf("select() timed out\n");
        free(socks_req);
        goto SOCK_ERR;
    }
    
    free(socks_req);
    
    response = malloc(SOCKS5_UDP_REPLY);
    memset(response, 0, SOCKS5_UDP_REPLY);
    res = recvTCP(usock->sk, SOCKS5_UDP_REPLY, response);
    if (res <= 0) {
        t = time(NULL);
        printf("DEBUG: recvTCP(2) failure at %s\n", ctime(&t)); /* Proxy close control connection */
        if (res == 0)
            printf("closed connection\n");
        if (res == -2)
            printf("select() timed out\n");
        free(response);
        goto SOCK_ERR;
    }
    
    usock->sk_ip = ((struct socks5_req *)response)->dst_ip;
    usock->sk_port = ((struct socks5_req *)response)->dstport;
    
    free(response);
    
    return OK;
SOCK_ERR:
    close(usock->sk);
    usock->sk = 0;
    return ERR;
}

void remove_connections(struct usock_t *usock, struct udps_config_t *conf) {
    void *tmp;
    struct conn_t *conn;
    
    conn = usock->conn;
    while (conn) {
        if (!conf || (conn->src_ip == conf->client_ip)) {
            tmp = (void *)conn;
            conn = conn->next;
            free(tmp);
        }
        else
            conn = conn->next;
    }
    
    return;
}

struct usock_t *find_connection(uint32_t sk_ip, uint16_t sk_port, uint32_t nat_ip, uint16_t src_port, u_int8_t inout) {
    struct usock_t *usock = default_usock;
    
    if (inout) {
        while (usock) {
            if ((usock->sk_ip == sk_ip) && (usock->sk_port == sk_port)
                && (usock->nat_ip == nat_ip) && (usock->src_port == src_port))
                return usock;
            usock = usock->next;
        }
    }
    else {
        while (usock) {
            if ((usock->connect_ip == sk_ip) && (usock->connect_port == sk_port)
                && (usock->nat_ip == nat_ip) && (usock->src_port == src_port))
                return usock;
            usock = usock->next;
        }
    }
        
    return NULL;
}
