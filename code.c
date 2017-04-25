#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>  

#include <netinet/ip_icmp.h>   
#include <netinet/udp.h>  
#include <netinet/tcp.h>  
#include <netinet/ip.h>   
#include <netinet/if_ether.h>  
#include <net/ethernet.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>


struct sockaddr_in source;
struct sockaddr_in dest;
int tcp=0,udp=0,icmp=0,igmp=0, http=0, dns=0, ftp=0,total=0,others=0,i,j;

//store http headers and payload
struct httphdr {
  unsigned char *headers;
  unsigned char *payload;
};

struct ftphdr {
  unsigned char *headers;
  unsigned char *payload;
};

struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
  };

  typedef struct list {
    struct iphdr* iph;
    struct ethhdr* eth;
    struct tcphdr* tcph;
    struct udphdr* udph;
    struct httphdr* httph;
    struct DNS_HEADER* dnsh;
    struct ftphdr* ftph;
    int size;
    struct list* next;
    int sno;
    unsigned char* bufo;
  }list;

  list* node;
  list** unilist;

  list* createListNode() {
    list* li = (list*) malloc (sizeof(list));
    li->iph = NULL;
    li->eth = NULL;
    li->tcph = NULL;
    li->udph = NULL;
    li->httph = NULL;
    li->dnsh = NULL;
    li->ftph = NULL;
    li->size = 0;
    li->next = NULL;
    li->bufo = NULL;
    return li;
  }
  int numb=0;
  void addtolist(list* temp) {
    unilist[count++] = temp; 
  }

  list* search(char* name) {
    int num = atoi(name);
    return unilist[num-1];
  }

  int istcp;

  int analyse_tcp_packet(unsigned char* buffer, list* node);
  int analyse_udp_packet(unsigned char *buffer, list* node);
  void extract_http_info(unsigned char *buffer, list* node);
  void extract_ftp_info(unsigned char *buffer, list* node) ;
  void extract_dns_info(unsigned char* buffer, list* node);
  void printDNS(GtkTextIter ei, GtkTextBuffer* buff, list* node);

  list* ProcessPacket(unsigned char* buffer)
  {
    //get ethernet header
    list* n1 = createListNode();
    struct ethhdr *eth = (struct ethhdr*)buffer;
    n1->eth = eth;
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    int iphdrlen = iph->ihl*4;
    n1->iph = iph;
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
      case 6:  //TCP Protocol
      ++tcp;
      int app_protocol = analyse_tcp_packet(buffer, n1);
      if(app_protocol == 1) {
        extract_http_info(buffer, n1);
      }
      else if(app_protocol == 4)
      {
        extract_ftp_info(buffer,n1);
      }
      else if(app_protocol == 2) {
        istcp = 1;
        extract_dns_info(buffer, n1);
      }
      break;
      case 17: //UDP Protocol
      ++udp;
      app_protocol = analyse_udp_packet(buffer, n1);
      istcp = 0;
			    if(app_protocol == 1) //dns
            extract_dns_info(buffer, n1);
          break;
      default: //Some Other Protocol like ARP etc.
      ++others;
      break;
    }
    return n1;
  }

  int analyse_tcp_packet(unsigned char* buffer, list* node)
  {
    unsigned short iphdrlen;
    int app_protocol;
    struct iphdr *iph = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    node->tcph = tcph;

	//to check application protocol
    if(ntohs(node->tcph->source) == 80 || ntohs(node->tcph->dest) == 80) app_protocol = 1;
    else if(ntohs(node->tcph->source) == 53 || ntohs(node->tcph->dest) == 53) app_protocol = 2;
    else if(ntohs(node->tcph->source) == 21 || ntohs(node->tcph->dest) == 21) app_protocol = 4;
    else app_protocol = 3;
    return app_protocol;
  }

  int analyse_udp_packet(unsigned char *buffer, list* node)
  {
    int app_protocol;
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    node->udph = udph;

    if(ntohs(udph->source) == 53 || ntohs(udph->dest) == 53) app_protocol = 1;
    else app_protocol = 2;
    return app_protocol;
  }

  void extract_http_info(unsigned char *buffer, list* node) {
  //while blank line
  //every line is new field with data
    int i;
    struct iphdr *iph = (struct iphdr *)(buffer +  sizeof(struct ethhdr));
    int iphdrlen = iph->ihl*4;
    int trans_hdr_len;

    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    trans_hdr_len = sizeof(struct ethhdr) + iphdrlen + sizeof tcph;

    i = trans_hdr_len;
    struct httphdr *hn = (struct httphdr*)malloc(sizeof(struct httphdr));
    node->httph = hn;
  }

  void extract_ftp_info(unsigned char *buffer, list* node) {

    int i;
    struct iphdr *iph = (struct iphdr *)(buffer +  sizeof(struct ethhdr));
    int iphdrlen = iph->ihl*4;
    int trans_hdr_len;

    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    trans_hdr_len = sizeof(struct ethhdr) + iphdrlen + sizeof tcph;

    i = trans_hdr_len;
    struct ftphdr *hn = (struct ftphdr*)malloc(sizeof(struct ftphdr));

    node->ftph = hn;
  }
  void extract_dns_info(unsigned char* buffer, list* node) {

    int app_protocol;
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    int header_size;

    if(!istcp) {
      struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
      header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    }
    else {
      struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
      header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof tcph;
    }

    struct DNS_HEADER* dnsh = (struct DNS_HEADER*)(buffer + header_size);
    node->dnsh=dnsh;



  }

