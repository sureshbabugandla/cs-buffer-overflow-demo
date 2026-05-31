/*
 * integer_server.c -- Integer/length bug enabling a buffer overflow 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>

#define PORT 9997

void handle_request(int client_fd) {
    char buffer[64];
    int len;                                   /* SIGNED length from attacker */

    if (recv(client_fd, &len, sizeof(len), 0) != sizeof(len)) return;

    /* Flawed bounds check: looks safe, but a negative len slips through. */
    if (len > (int)sizeof(buffer)) {           /* e.g. 200 > 64 -> rejected   */
        dprintf(client_fd, "rejected: too long\n");
        return;
    }

    /* len is converted to size_t here. If len == -1, this becomes SIZE_MAX,
       so recv copies as many bytes as the attacker sends -> overflow. */
    ssize_t n = recv(client_fd, buffer, (size_t)len, 0);
    if (n <= 0) return;
    buffer[ n < (ssize_t)sizeof(buffer) ? n : (ssize_t)sizeof(buffer)-1 ] = '\0';
    dprintf(client_fd, "stored %zd bytes\n", n);
}

int main(void){
    signal(SIGCHLD, SIG_IGN);
    int srv=socket(AF_INET,SOCK_STREAM,0); int opt=1;
    setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons(PORT); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(srv,(struct sockaddr*)&a,sizeof(a))<0){perror("bind");return 1;}
    listen(srv,8);
    printf("[integer server] listening on 0.0.0.0:%d\n",PORT); fflush(stdout);
    for(;;){int c=accept(srv,NULL,NULL); if(c<0)continue;
        if(fork()==0){close(srv); handle_request(c); close(c); _exit(0);} close(c);}
}
