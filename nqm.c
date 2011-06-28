/***********************************************************************
 * nqm.c : Handles the TCP/UDP header parseing of raw IP packets
 ***********************************************************************/

#include "udps.h"

/* 
 * This fuction identifies if the captured packet is TCP or UDP.
 * Fuction will return: Protocol code e.g.  1 for ICMP, 6 for TCP and 17 for UDP.
 */
int identify_ip_protocol(unsigned char *payload) {
    return payload[9];
}

/*
 * This function gets src IP as string
 */
char *get_src_ip_str(unsigned char *payload) {
    /* Cast the IP Header from the raw packet */
    struct ip *iph = (struct ip *) payload;
    
    /* get src address from iph */
    return(inet_ntoa(iph->ip_src));
}

/*
 * This function gets dst IP as string
 */
char *get_dst_ip_str(unsigned char *payload) {
    /* Cast the IP Header from the raw packet */
    struct ip *iph = (struct ip *) payload;
    
    /* get dst address from iph */
    return(inet_ntoa(iph->ip_dst));
}

/* 
 * This function gets tcp src port from captured packet TCP.
 * Returns source port of the packet
 */
int get_tcp_src_port(unsigned char *payload) {	
    unsigned char *pkt_data_ptr = NULL;	
    pkt_data_ptr = payload + sizeof(struct ip);
    
    /* Cast the TCP Header from the raw packet */
    struct tcphdr *tcph = (struct tcphdr *) pkt_data_ptr;
    
    /* get the source port of the packet */
    return(ntohs(tcph->th_sport));
}

/* 
 * This function returns the destination port of the captured packet TCP.
 * returns destination port 
 */
int get_tcp_dst_port(unsigned char *payload) {
    unsigned char *pkt_data_ptr = NULL;
    pkt_data_ptr = payload + sizeof(struct ip);
    
    /* Cast the TCP Header from the raw packet */
    struct tcphdr *tcph = (struct tcphdr *) pkt_data_ptr;
    
    /* get the destination port of the packet */
    return(ntohs(tcph->th_dport));
}

/*
 * This function returns the source port of the captured packet UDP
 */
int get_udp_src_port(unsigned char *payload) {
    unsigned char *pkt_data_ptr = NULL;	
    pkt_data_ptr = payload + sizeof(struct ip);
    
    /* Cast the UDP Header from the raw packet */
    struct udphdr *udp = (struct udphdr *) pkt_data_ptr;
    
    /* get the source port of the packet */
    return(ntohs(udp->uh_sport));
}

/*
 * This function returns the destination port of the captured packet UDP
 */
int get_udp_dst_port(unsigned char *payload) {
    unsigned char *pkt_data_ptr = NULL;	
    pkt_data_ptr = payload + sizeof(struct ip);
    
    /* Cast the UDP Header from the raw packet */
    struct udphdr *udp = (struct udphdr *) pkt_data_ptr;
    
    /* get the dst port of the packet */
    return(ntohs(udp->uh_dport));
}
