#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define sz 			1000
#define mute_sz 	5 

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

	unsigned char ipm[sz];   
	int nm; 

	FILE *fm = fopen("mute.bin", "rb"); 
	if (!fm) {
		perror("[-] Error when opening mute packet");
		exit(1); 
	}
	nm = fread(ipm, 1, sz, fm); 

	char table[] = "abcdefghijklmnopqrstuvwxyz"; 

	while (1) {
	// for (int i = 0; i < 65535; i++) {
		char mute[mute_sz]; 
		for (int j = 0; j < mute_sz; j++)
			mute[j] = table[rand() % 26]; 
		memcpy(ipm + 0x29, mute, mute_sz); 
		send_pkt(ipm, nm);
		sleep(1);
	}

	return 0; 
}