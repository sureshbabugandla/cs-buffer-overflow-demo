/*
 * leak_server.c -- Stack-based information-disclosure demo 
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
    /* Layout is deterministic inside a struct: buffer first, secret right after. */
    struct {
        char buffer[32];      /* attacker input */
        char secret[64];      /* "sensitive" data sitting on the same stack */
    } f;

    /* Simulate sensitive data already present in this stack frame. */
    snprintf(f.secret, sizeof(f.secret),
             "ACCT 4012-8888-1881 BAL $92,450 PIN 7263");

    ssize_t n = recv(client_fd, f.buffer, sizeof(f.buffer), 0);  /* up to 32 */
    if (n <= 0) return;

    /* BUG: if the client sent 32 bytes, f.buffer has NO terminator.
       %s then reads through f.buffer and into f.secret. */
    dprintf(client_fd, "Server received: %s\n", f.buffer);
}

int main(void) {
    signal(SIGCHLD, SIG_IGN);
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons(PORT); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if (bind(srv,(struct sockaddr*)&a,sizeof(a))<0){perror("bind");return 1;}
    listen(srv,8);
    printf("[leak server] listening on 0.0.0.0:%d\n", PORT); fflush(stdout);
    for(;;){
        int c=accept(srv,NULL,NULL); if(c<0) continue;
        if(fork()==0){ close(srv); handle_request(c); close(c); _exit(0);}
        close(c);
    }
}
