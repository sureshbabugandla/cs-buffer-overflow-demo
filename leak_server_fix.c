/*
 * leak_server_fix.c -- FIXED version of leak_server.c (data disclosure demo).
 * Course: Software Security (MTech), Group G25AIT
 *
 * Fix for CWE-125/CWE-200: reserve one byte, always null-terminate the input,
 * and print with a bounded conversion (%.*s) so %s can never read past the
 * buffer into the adjacent secret.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>

#define PORT 9998

void handle_request(int client_fd) {
    struct {
        char buffer[32];
        char secret[64];
    } f;
    snprintf(f.secret, sizeof(f.secret), "ACCT 4012-8888-1881 BAL $92,450 PIN 7263");

    /* FIX: leave room for a terminator and never fill the whole buffer. */
    ssize_t n = recv(client_fd, f.buffer, sizeof(f.buffer) - 1, 0);
    if (n <= 0) return;
    f.buffer[n] = '\0';                       /* always terminate */

    /* FIX: bounded output -- print exactly n bytes, never run into secret. */
    dprintf(client_fd, "Server received: %.*s\n", (int)n, f.buffer);
}

int main(void){
    signal(SIGCHLD, SIG_IGN);
    int srv=socket(AF_INET,SOCK_STREAM,0); int opt=1;
    setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons(PORT); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(srv,(struct sockaddr*)&a,sizeof(a))<0){perror("bind");return 1;}
    listen(srv,8);
    printf("[leak_server_fix] listening on 0.0.0.0:%d\n",PORT); fflush(stdout);
    for(;;){int c=accept(srv,NULL,NULL); if(c<0)continue;
        if(fork()==0){close(srv); handle_request(c); close(c); _exit(0);} close(c);}
}
