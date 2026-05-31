/*
 * server_fix.c -- FIXED version of server.c (control-flow hijack demo).
 * Course: Software Security (MTech), Group G25AIT
 *
 * Fix for CWE-121: the copy is bounded to the destination size, so the
 * over-length request is truncated instead of overflowing the stack and
 * overwriting the saved return address. give_shell() can no longer be reached.
 * Build with the protections on (canary, NX, PIE, RELRO) -- see notes below.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>

#define PORT 9999

/* Present in the binary but now unreachable: the overflow can't redirect here. */
void give_shell(void) {
    /* left in place only to mirror the vulnerable version; never reached */
}

void handle_request(int client_fd) {
    char buffer[64];
    char request[2048];

    ssize_t n = recv(client_fd, request, sizeof(request) - 1, 0);
    if (n <= 0) return;

    /* FIX: never copy more than the buffer can hold, and terminate. */
    size_t copy = (size_t)n < sizeof(buffer) - 1 ? (size_t)n : sizeof(buffer) - 1;
    memcpy(buffer, request, copy);
    buffer[copy] = '\0';

    dprintf(client_fd, "Server received: %s\n", buffer);
}

int main(void){
    signal(SIGCHLD, SIG_IGN);
    int srv=socket(AF_INET,SOCK_STREAM,0); int opt=1;
    setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons(PORT); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(srv,(struct sockaddr*)&a,sizeof(a))<0){perror("bind");return 1;}
    listen(srv,8);
    printf("[server_fix] listening on 0.0.0.0:%d\n",PORT); fflush(stdout);
    for(;;){int c=accept(srv,NULL,NULL); if(c<0)continue;
        if(fork()==0){close(srv); handle_request(c); close(c); _exit(0);} close(c);}
}
