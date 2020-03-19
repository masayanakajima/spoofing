#include <sys/socket.h>

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct ether_hdr{
	unsigned char ether_dest_addr[ETHER_ADDR_LEN];
	unsigned char ether_src_addr[ETHER_ADDR_LEN];
	unsigned short ether_type;
};

struct arp_hdr{
	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char hardware_size;
	unsigned char protocol_size;
	unsigned short opcode;
	unsigned char sender_mac[6];
	unsigned char sender_ip[4];
	unsigned char target_mac[6];
	unsigned char target_ip[4];
};

struct ip_hdr{
	unsigned char ip_version_and_header_length;
	unsigned char ip_tos;
	unsigned short ip_len;
	unsigned short ip_id;
	unsigned short ip_frag_offset;
	unsigned char ip_ttl;
	unsigned char ip_type;
	unsigned char ip_checksum[2];
	unsigned char ip_src_addr[4];
	unsigned char ip_dest_addr[4];
};

struct tcp_hdr{
	unsigned short tcp_src_port;
	unsigned short tcp_dest_port;
	unsigned int tcp_seq;
	unsigned int tcp_ack;
	unsigned char reserverd:4;
	unsigned char tcp_offset:4;
	unsigned char tcp_flags;
	#define TCP_FIN 0x01
	#define TCP_SYN 0x02
	#define TCP_RST 0x04
	#define TCP_PUSH 0x08
	#define TCP_ACK 0x10
	#define TCP_URG 0x20
	unsigned short tcp_window;
	unsigned short tcp_checksum;
	unsigned short tcp_urgent;
};

struct arp_packet{
	struct ether_hdr ether;
	struct arp_hdr arp;
};


void dump(const unsigned char *data_buffer,const unsigned int length){
	unsigned char byte;
	unsigned int i,j;
	for(i=0;i<length;i++){
		byte=data_buffer[i];
		printf("%02x ",data_buffer[i]);
		if(((i%16)==15)||(i==length-1)){
			for(j=0;j<16-(i%16);j++)
				printf("   ");
			printf("|");
			for(j=(i-(i%16));j<=i;j++){
				byte=data_buffer[j];
				if((byte>31)&&(byte<127))
					printf("%c",byte);
				else
					printf(".");
			}		
			printf("\n");		
		}
	}
}

//macアドレスが等しければ0を返す
int compare_mac(u_char* adr1,u_char*adr2){
	for(int i=0;i<6;i++){
		if(adr1[i]!=adr2[i])
			return 1;
	}
	return 0;
}

//ipアドレスが等しければ０を返す
int compare_ip(u_char* adr1,u_char*adr2){
	for(int i=0;i<4;i++){
		if(adr1[i]!=adr2[i])
			return 1;
	}
	return 0;
}



//pcapエラー表示
void pcap_fatal(const char* failed_in, const char* errbuf){
    printf("fatal error:%s,%s\n",failed_in,errbuf);
}


//2byte10進数をリトルエンディアン１０進数に直す
short ledecimal(short var){
    int fo=var/256;
    int so=var%256;

    return so*256+fo;
}

