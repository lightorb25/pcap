#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define ETHERNET_ADDLEN 6
#define size_ethernet 14
#define IP_HL(ip) (((ip)->ip_vhl) &0x0f)
const u_char* packet;

struct ethernet_hdr //14bit
{
	u_char	ether_dhost[ETHERNET_ADDLEN]; //6bit
	u_char	ether_shost[ETHERNET_ADDLEN]; //6bit
	u_short ether_type; //2bit
};

struct ip_hdr 
{
	u_char ip_vhl; //4bit version + 4bit header length
	u_char ip_tos; //8bit Type Of Service
	u_short ip_len; //16bit TotalLength
	u_short ip_id;  //16bit identification
	u_short ip_off; //IPflags, Fragment Offset
		#define IP_RF 0x8000 // reserved(evil bit)
		#define IP_DF 0x4000 // do not fragment
		#define IP_MF 0x2000 // more fragments follow
		#define IP_OFFMASK 0x1fff // offset mask
	u_char ip_ttl; //8bit time to live
	u_char ip_p; //8bit protocol
	u_short ip_sum; //8bit header check sum
	struct in_addr ip_src; //32bit Source Addr
	struct in_addr ip_dst; //32bit Destination Addr
	u_long ip_option; //32bit ip option
};


struct tcp_hdr 
{
	u_short th_sport; //16bit scr port
	u_short	th_dport; //16bit dst port
	u_int th_seq; //32bit seq num
	u_int th_ack; //32bit ack num
	u_char th_offx2; //4bit header length + 6bit reserved
	#define TH_OFF(th) (((th) ->th_offx2 & 0xf0) >> 4)
	u_char th_flags; //6bit control bit
		#define TH_FIN 0x01  //finish
		#define TH_SYN 0x02 //synchronize
		#define TH_RST 0x04 //reset
		#define TH_PUSH 0x08 //push
		#define TH_ACK 0x10 //acknowledgment
		#define TH_URG 0x20 //urgent
		#define TH_ECE 0x40 //explicit congestion notification
		#define TH_CWR 0x80 //congestion window reduced
		#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win; //16bit window size
	u_short th_sum; //16bit checksum
	u_short th_urp; //16bit urgent point
	u_long th_option; //32bit tcp options

};

struct ethernet_hdr *ethernet;
struct ip_hdr *ip;
struct tcp_hdr *tcp;
u_char *payload;
u_char *data;
u_int size_tcp; 
u_int size_ip;

void parshing(u_int p_len) 
{
	printf("-------------------------------------------------------------\n");
	int i,payload_len,data_len;
	ethernet = (struct ethernet_hdr*) (packet);
	printf("MAC Source :");
	for(i=0; i<ETHERNET_ADDLEN; i++)
	{
		printf("%02x ", ethernet -> ether_shost[i]);
	}
	
	printf("MAC Dest :");
        for(i=0; i<ETHERNET_ADDLEN; i++)
        {
                printf("%02x ", ethernet -> ether_dhost[i]);
        }
	
	ip = (struct ip_hdr*)(packet + size_ethernet);
	size_ip = IP_HL(ip)*4;
	printf("\nIP Source : %s\n", inet_ntoa(ip->ip_src));
	printf("IP Dest : %s\n", inet_ntoa(ip->ip_dst));

	tcp = (struct tcp_hdr*)(packet + size_ethernet + size_ip);
	size_tcp = TH_OFF(tcp)*4; 
	printf("PORT Source : %2d\n", ntohs(tcp->th_sport));
	printf("PORT dest : %2d\n", ntohs(tcp->th_dport));
	
	payload = (u_char *)(packet + size_ethernet + size_ip + size_tcp);
	payload_len = ntohs(ip->ip_len) - (size_ip+size_tcp);
	if(payload_len == 0) printf("no payload.\n");
	else 
	{
		printf("payload>>\n");
		for(i=1;i<17;i++)
		{
			printf("%02x ", payload[i - 1] );
		}
	}
}



void usage() 
{
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) 
{
  if (argc != 2) 
  {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) 
  {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) 
  {
    struct pcap_pkthdr* header;
    u_int pk_len;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    pk_len = header->caplen;
    parshing(pk_len);
    printf("\n%u bytes captured\n", pk_len);
    printf("-------------------------------------------------------------\n");
  }

  pcap_close(handle);
  return 0;
}
