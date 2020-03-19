#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "hacking.h"

#define PORT 80
#define WEBROOT "./webroot"
#define LOGFILE "/var/log/tinywebd.log"

int logfd,sockfd;
void handle_connection(int,struct sockaddr_in*,int);
int get_file_size(int);
void timestamp(int);

void handle_shutdown(int signal){
    timestamp(logfd);
    write(logfd,"シャットダウンします。\n",16);
    close(logfd);
    close(sockfd);
    exit(0);
}

int main(void){
    int new_sockfd,yes=1;
    struct sockaddr_in host_addr,client_addr;
    socklen_t sin_size;

    logfd=open(LOGFILE,O_WRONLY|O_CREAT|O_APPEND,S_IRUSR|S_IWUSR);
    if(logfd==-1)
        fatal("ログファイルのオープンに失敗しました。");

    if((sockfd=socket(PF_INET,SOCK_STREAM,0))==-1)
        fatal("ソケットの生成に失敗しました。");

    if(setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int))==-1)
        fatal("ソケットオプションSO_REUSEADDRの設定に失敗しました。");

    printf("tinywebデーモンを開始します。\n");
    if(daemon(1,0)==-1)
        fatal("デーモンプロセスのフォークに失敗しました。");

    signal(SIGTERM,handle_shutdown);
    signal(SIGINT,handle_shutdown);

    timestamp(logfd);
    write(logfd,"起動中。\n",15);
    host_addr.sin_family=AF_INET;
    host_addr.sin_port=htons(PORT);
    host_addr.sin_addr.s_addr=INADDR_ANY;
    memset(&(host_addr.sin_zero),'\0',8);

    if(bind(sockfd,(struct sockaddr*)&host_addr,sizeof(struct sockaddr))==-1)
        fatal("ソケットのバインドに失敗しました。");

    if(listen(sockfd,20)==-1)
        fatal("ソケットの待受に失敗しました。");

    while(1){
        sin_size=sizeof(struct sockaddr_in);
        new_sockfd=accept(sockfd,(struct sockaddr*)&client_addr,&sin_size);
        if(new_sockfd==-1)
            fatal("コネクションの受付に失敗しました。");

        handle_connection(new_sockfd,&client_addr,logfd);
    }

    return 0;

}


