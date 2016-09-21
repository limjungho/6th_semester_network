#include <winsock2.h>
#define ETH_ALEN   6                
#define ETHERTYPE_PUP       0x0200      /* Xerox PUP */
#define ETHERTYPE_IP        0x0800      /* IP */
#define ETHERTYPE_ARP       0x0806      /* Address resolution */
#define ETHERTYPE_REVARP    0x8035      /* Reverse ARP */
#define IPTOS_TOS_MASK      0x1E
#define IPTOS_TOS(tos)      ((tos)&IPTOS_TOS_MASK)
#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
#define IPTOS_LOWCOST       0x02

struct ether_header
{
	unsigned char ether_dhost[ETH_ALEN];
	unsigned char ether_shost[ETH_ALEN];
	unsigned short ether_type;
};

#pragma pack(1)
struct ip_header {

	unsigned char  ip_hl : 4; // ��� ����
	unsigned char  ip_v : 4; // ����
	u_char  ip_tos;  // ���� Ÿ��
	u_short  ip_len;  // ��ü����
	u_short  ip_id;  // �ĺ���
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff 
	u_short      ip_off;  // �÷���, ������ �ʵ�

	//u_int_t    ip_ttl;  // TTL(Time To Live)
	//u_int8_t    ip_p;   // ��������
	u_short     ip_sum;  // üũ��
	struct in_addr ip_src; // ����� IP�ּ�
	struct in_addr ip_dst; // ������ IP�ּ�
};
#pragma pack()                              //////by BusanIT EHA WonJae