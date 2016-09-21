#include "pcap.h"

#include <stdio.h>
#include <winsock2.h>

#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )

#define FILTER_RULE "host 127.0.0.1"

struct ether_addr //이더넷 주소 구조체
{
	unsigned char ether_addr_octet[6];
};

struct ether_header  //이더넷 헤더 구조체
{
	struct  ether_addr ether_dhost;
	struct  ether_addr ether_shost;
	unsigned short ether_type;
};

struct ip_header   //ip 헤더 구조체
{
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_frag_offset : 5;
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
};

struct tcp_header   //tcp 헤더 구조체
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};

void print_ether_header(const unsigned char *data);  //이더넷 헤더 출력 함수
int print_ip_header(const unsigned char *data);  //ip 헤더 출력 함수
int print_tcp_header(const unsigned char *data);  //tcp 헤더 출력 함수
void print_data(const unsigned char *data);  //나머지 data 출력 함수

int main() {
	pcap_if_t *alldevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	int offset = 0;

	// 네트워크 어댑터 검색
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("Devices Find Failed\n");
		return -1;
	}
	if (alldevs == NULL) {
		printf("No Devices Found\n");
		return -1;
	}
	// 찾은 네트워크 어댑터 목록 출력
	pcap_if_t *d; int i;
	for (d = alldevs, i = 0; d != NULL; d = d->next) {
		printf("%d. %s ", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	int inum;
	// 받을 인터페이스 입력
	printf("Enter the interface number: ");
	scanf("%d", &inum);
	for (d = alldevs, i = 0; i<inum - 1; d = d->next, i++); // i번째 device로 설정

	//pcap 오픈				
	pcap_t  *fp;
	if ((fp = pcap_open_live(d->name,      // name of the device
		65536,                   // capture size
		1,  // promiscuous mode
		20,                    // read timeout
		errbuf
	)) == NULL) {
		printf("pcap open failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("pcap open Successful\n");


	//pcap 컴파일
	struct bpf_program  fcode;
	if (pcap_compile(fp,  // pcap handle
		&fcode,  // compiled rule
		FILTER_RULE,  // filter rule
		1,            // optimize
		NULL) < 0) {
		printf("pcap compile failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(fp, &fcode) <0) {
		printf("pcap compile failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	pcap_freealldevs(alldevs); // 디바이스 찾아놓은 것 free

	struct pcap_pkthdr *header;

	const unsigned char *pkt_data;
	int res;

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) { //마지막으로 캡처한 pcap을 res로
		if (res == 0) continue;

		print_ether_header(pkt_data);
		pkt_data = pkt_data + 14;       // raw_pkt_data의 14번지까지 이더넷
		offset = print_ip_header(pkt_data);
		pkt_data = pkt_data + offset;           // ip_header의 길이만큼 오프셋
		offset = print_tcp_header(pkt_data);
		pkt_data = pkt_data + offset;           //print_tcp_header *4 데이터 위치로 오프셋
		print_data(pkt_data);
	}


	return 0;

}

void print_ether_header(const unsigned char *data)
{
	struct  ether_header *eh;               // 이더넷 헤더 구조체
	unsigned short ether_type;
	eh = (struct ether_header *)data;       // 받아온 로우 데이터를 이더넷 헤더구조체 형태로 사용
	ether_type = ntohs(eh->ether_type);       // 숫자는 네트워크 바이트 순서에서 호스트 바이트 순서로 바꿔야함

	if (ether_type != 0x0800)
	{
		printf("ether type wrong\n");
		return;
	}
	// 이더넷 헤더 출력
	printf("\nETHERNET HEADER\n");
	// 이더넷의 source mac address, destination mac address 출력

	printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for src
		eh->ether_shost.ether_addr_octet[0],
		eh->ether_shost.ether_addr_octet[1],
		eh->ether_shost.ether_addr_octet[2],
		eh->ether_shost.ether_addr_octet[3],
		eh->ether_shost.ether_addr_octet[4],
		eh->ether_shost.ether_addr_octet[5]);
	printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for dest
		eh->ether_dhost.ether_addr_octet[0],
		eh->ether_dhost.ether_addr_octet[1],
		eh->ether_dhost.ether_addr_octet[2],
		eh->ether_dhost.ether_addr_octet[3],
		eh->ether_dhost.ether_addr_octet[4],
		eh->ether_dhost.ether_addr_octet[5]);
}

int print_ip_header(const unsigned char *data)
{
	struct  ip_header *ih;
	ih = (struct ip_header *)data;  // ip_header의 구조체 형태로 변환

	printf("\nIP HEADER\n");

	//IP 헤더의 source ip address와 destination ip address 출력
	printf("Src IP Addr : %s\n", inet_ntoa(ih->ip_srcaddr));
	printf("Dst IP Addr : %s\n", inet_ntoa(ih->ip_destaddr));

	// 헤더 사이즈만큼 오프셋 반환
	return ih->ip_header_len * 4;
}

int print_tcp_header(const unsigned char *data)
{
	struct  tcp_header *th;
	th = (struct tcp_header *)data;

	printf("\nTCP HEADER\n");
	//TCP 헤더의 source port number와 destination port number 출력
	printf("Src Port Num : %d\n", ntohs(th->source_port));
	printf("Dest Port Num : %d\n", ntohs(th->dest_port));

	// 헤더 사이즈만큼 오프셋 반환
	return th->data_offset * 4;
}

void print_data(const unsigned char *data)
{
	printf("\nDATA\n");
	// 나머지 DATA 출력
	printf("%s\n", data);
}