#include "dnsdetect.h"

#define DBG printf( "Line:%s\n",__LINE__);
#define PREV_SIZE 8

struct info {
	ushort id;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_prt;
	uint16_t dst_prt;
	char domain_ip[16];
};

struct info* prev[PREV_SIZE];

void process_packet(u_char *string, const struct pcap_pkthdr *header,
        const u_char *packet)
{
	HEADER *dns;
	u_char *p, *pktend;
	char buf[1024];
	int i, dnslen;
	in_addr_t dst_ip=NULL;
	u_short dnstype, dnsclass;
    struct libnet_ipv4_hdr *ip;
    struct libnet_udp_hdr *udp;
	char domain[MAXHOSTNAMELEN];

    ip = (struct libnet_ipv4_hdr *)(packet + SIZE_ETHERNET);
    udp = (struct libnet_udp_hdr *)(packet + SIZE_ETHERNET + (ip->ip_hl * 4));
    dns = (HEADER *)(udp + 1);

    p = (u_char *)(dns + 1);

    pktend = (u_char *)packet + header->caplen;
    if ((dnslen = pktend - (u_char *)dns) < sizeof(*dns))
        return;

	i = dn_expand((u_char *)dns, pktend, p, domain, sizeof(domain));
	if( i<0)
		return;
	p += i;
	GETSHORT(dnstype, p);
	GETSHORT(dnsclass, p);

	if(dnstype!=T_A)
		return;

	ushort id;
	GETSHORT(id, dns);
		
	p = p +12;
	struct in_addr ip_add;
	static int count=0;
	memcpy(&ip_add, p, 16);
	char *ip_new = inet_ntoa(ip_add);

	i=0;
	int j=0;
	char* list_ips[PREV_SIZE];
	
	for (i=0; i<PREV_SIZE; i++) {
		if (id == prev[i]->id &&
			 prev[i]->src_ip==ip->ip_src.s_addr && prev[i]->dst_ip==ip->ip_dst.s_addr &&
//			 prev->[i]src_prt==udp->uh_sport && prev[i]->dst_prt==udp->uh_dport &&
			 strcmp(prev[i]->domain_ip, ip_new)) {
			list_ips[j++] = prev[i]->domain_ip;
		}
	}
	
	if (j>0) {
		printf("DNS poisoning attempt\n");
		printf("TXID: %d Request: %s\n", id, domain);
		printf("Answer1: %s\n", ip_new);
		printf("Answer2: ");
		
		for (i=0; i< j; i++) 
			printf("%s \n", list_ips[i]);
		printf("\n");
	}
	j=0;
	
	prev[count]->id = id;
	prev[count]->src_ip= ip->ip_src.s_addr;
	prev[count]->dst_ip= ip->ip_dst.s_addr;
	prev[count]->src_prt= udp->uh_sport;
	prev[count]->dst_prt= udp->uh_dport;
	memcpy(prev[count]->domain_ip, ip_new,16);

	count++;
	count = count %5;

    return;
}


int main(int argc, char* argv[])
{
	char* interface=NULL;
	char* file=NULL;
	char* expression=NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net = 0;        
	u_int mask = 0;
	int  ch;
	pcap_t *handle;


	while ((ch = getopt(argc, argv, "i:r:")) != -1) {
		switch(ch) {
		case 'i': 
				interface = optarg; 
			break;
		
		case 'r':
				file  = optarg;
			break;
		case '?':
				printf("Enter valid arguments\n");
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

	char exp[16+exp_len];
	if (expression) {
		sprintf(exp, "udp port 53 and ");
		sprintf(exp +16 , "%s", expression);
	} else {
		sprintf(exp, "udp port 53");
		exp[12] = '\0';
	}

	printf("exp: %s\n",exp);    

    if (interface && file) {
        printf(" Use only one option: Interface or file\n");
        return 1;
    }

    if (!interface && !file) {

        interface = pcap_lookupdev(errbuf);
        if (interface == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return 1;
        }
    }

    if (interface) {
    	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	    if (handle == NULL) {
		    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		    return 1;
	    }
    }else if (file) {
        handle = pcap_open_offline(file, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
            return 1;
        }
    } else {
        return 1;
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

    if(interface) {
        printf("listening on  %s,", interface);
    } else {
        printf("reading from file  %s,", file);
    }
    printf(" link-type EN10MB (Ethernet)\n");
	
	int i=0;
	for(i=0; i<PREV_SIZE; i++) {
		prev[i] = (struct info*)malloc(sizeof(struct info));
		memset(prev[i],0, sizeof(struct info));
	}

    pcap_loop(handle, 0, process_packet, NULL);
	
    pcap_close(handle);

	printf("Complete\n");
    return 0;
}    
