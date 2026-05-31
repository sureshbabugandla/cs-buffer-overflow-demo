/*
 * dos_server_fix.c -- FIXED version of dos_server.c (denial-of-service demo).
 * Course: Software Security (MTech), Group G25AIT
 *
 * Two-part fix:
 *   1) CWE-121 root cause: bound the copy so the overflow can't happen.
 *   2) Resilience: fork a child per client, so even if a handler were to crash
 *      it would only kill that child -- the listening server keeps serving.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>

#define PORT 9996

void handle_request(int c) {
    char buffer[64];
    char staging[8192];
    ssize_t n = recv(c, staging, sizeof(staging), 0);
    if (n > 0) {
        /* FIX: never copy more than the destination holds. */
        size_t copy = (size_t)n < sizeof(buffer) ? (size_t)n : sizeof(buffer) - 1;
        memcpy(buffer, staging, copy);
        buffer[copy < sizeof(buffer) ? copy : sizeof(buffer)-1] = '\0';
        dprintf(c, "ok: %zu bytes (truncated to buffer)\n", copy);
    }
}

int main(void){
    signal(SIGCHLD, SIG_IGN);                 /* FIX: reap children */
    int srv=socket(AF_INET,SOCK_STREAM,0); int opt=1;
    setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons(PORT); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(srv,(struct sockaddr*)&a,sizeof(a))<0){perror("bind");return 1;}
    listen(srv,8);
    printf("[dos_server_fix] listening on 0.0.0.0:%d (forking)\n",PORT); fflush(stdout);
    for(;;){
        int c=accept(srv,NULL,NULL); if(c<0) continue;
        if(fork()==0){ close(srv); handle_request(c); close(c); _exit(0); }  /* FIX: per-client child */
        close(c);
    }
}
