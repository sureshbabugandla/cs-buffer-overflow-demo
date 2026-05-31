/*
 * integer_server_fix.c -- FIXED version of integer_server.c.
 * Course: Software Security (MTech), Group G25AIT
 *
 * Fix for CWE-190/CWE-20: validate BOTH ends of the range, and reject any
 * non-positive length. A negative value (e.g. -1) is now caught by the
 * "len <= 0" check before it can be converted to a huge size_t.
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
    int len;
    if (recv(client_fd, &len, sizeof(len), 0) != sizeof(len)) return;

    /* FIX: reject non-positive AND too-large lengths. The "len <= 0" test
       catches negative values that the original "len > 64" check missed. */
    if (len <= 0 || len > (int)sizeof(buffer) - 1) {
        dprintf(client_fd, "rejected: bad length\n");
        return;
    }

    ssize_t n = recv(client_fd, buffer, (size_t)len, 0);
    if (n <= 0) return;
    buffer[n] = '\0';
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
    printf("[integer_server_fix] listening on 0.0.0.0:%d\n",PORT); fflush(stdout);
    for(;;){int c=accept(srv,NULL,NULL); if(c<0)continue;
        if(fork()==0){close(srv); handle_request(c); close(c); _exit(0);} close(c);}
}
