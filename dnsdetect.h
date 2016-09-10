#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <resolv.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>
#include <time.h>

/* Ethernet addresses are 6 bytes */
#define SIZE_ETHERNET 14
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV4 0x0800
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 

    /* Ethernet header */
struct sniff_ethernet {
    u_char dst[ETHER_ADDR_LEN]; /* Destination host address */
    u_char src[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
 };

    /* IP header */
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};

    /* TCP header */
    typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    tcp_seq th_seq;     /* sequence number */
    tcp_seq th_ack;     /* acknowledgement number */
    u_char th_offx2;    /* data offset, rsvd */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};

struct sniff_udp {
	u_short sport;	/* source port */
	u_short dport;	/* destination port */
	u_short udp_length;
	u_short udp_sum;	/* checksum */
};

struct sniff_arp { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
}arphdr_t; 

