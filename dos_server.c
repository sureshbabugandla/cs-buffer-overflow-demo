/*
 * dos_server.c -- Denial-of-Service via buffer overflow crash (LAB ONLY).
 * Course: Software Security (MTech), Group G25AIT
 * Vulnerability: CWE-121 overflow -> CWE-400 availability loss.
 *
 * SINGLE-PROCESS (non-forking): handles one client at a time. The vulnerable
 * copy is in handle_request(), which RETURNS -- so an oversized request
 * overwrites the saved return address and the process crashes on return,
 * taking the whole (non-forking) service down for every future client.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 9996

/* Vulnerable handler: unbounded copy into a 64-byte buffer. Because this
   function RETURNS, a large enough overflow corrupts the saved return address
   and the process crashes when handle_request() returns. */
void handle_request(int c) {
    char buffer[64];
    char staging[8192];
    ssize_t n = recv(c, staging, sizeof(staging), 0);
    if (n > 0) {
        memcpy(buffer, staging, n);          /* no bound -> overflow */
        dprintf(c, "ok: %zd bytes\n", n);
    }
}

int main(void){
    int srv=socket(AF_INET,SOCK_STREAM,0); int opt=1;
    setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons(PORT); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(srv,(struct sockaddr*)&a,sizeof(a))<0){perror("bind");return 1;}
    listen(srv,8);
    printf("[dos server] listening on 0.0.0.0:%d (single-process)\n",PORT); fflush(stdout);
    for(;;){
        int c=accept(srv,NULL,NULL); if(c<0) continue;
        handle_request(c);     /* if this crashes, the whole server dies */
        close(c);
    }
}