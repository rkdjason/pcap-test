#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>

#define	ETHER_ADDR_LEN	6	/* length of an Ethernet address */

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};


void print_mac(char *msg, uint8_t *mac) {
    printf("%s", msg);
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */

    u_int8_t ip_tos;       /* type of service */

    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;

    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */

    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */

    u_int8_t  th_flags;       /* control flags */

    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

void print_payload(char* msg, const u_char *payload, int payload_len){
	printf("%s", msg);
	if (payload_len > 20){
		for (int i=0; i < 20; i++){
			printf("%02X ", payload[i]);
		}
	}
	else if (payload_len > 0){
		for (int i=0; i < payload_len; i++){
			printf("%02X ", payload[i]);
		}
	}
	else{
		printf("None");
	}
	printf("\n\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		printf("%u bytes captured\n", header->caplen);

		struct libnet_ethernet_hdr *ether = (struct libnet_ethernet_hdr *)packet;
		int ether_hlen = sizeof(struct libnet_ethernet_hdr);
		struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)(packet + ether_hlen);
		int ip_hlen = ip->ip_hl * 4;
		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)(packet + ether_hlen + ip_hlen);
		int tcp_hlen = tcp->th_off * 4;
		int payload_len = header->caplen - (ether_hlen + ip_hlen + tcp_hlen);

		if (ntohs(ether->ether_type) != 0x0800) continue;
		if (ip->ip_p != 6) continue;
		
		printf("[Ethernet Header]\n");
		print_mac("src MAC: ", ether->ether_shost);
		print_mac("dst MAC: ", ether->ether_dhost);

		printf("[IP Header]\n");
		printf("src IP: %s\n", inet_ntoa(ip->ip_src));
		printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));

		printf("[TCP Header]\n");
		printf("src port: %d\n", ntohs(tcp->th_sport));
		printf("dst port: %d\n", ntohs(tcp->th_dport));
		
		print_payload("Payload: ", packet + ether_hlen + ip_hlen + tcp_hlen, payload_len);
	}

	pcap_close(pcap);
}
