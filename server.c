/*
 * server.c -- Intentionally vulnerable TCP server 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>

#define PORT 9999

/* The client socket fd for the current child. Set in main's child branch so
 * give_shell() can reach it without needing arguments (simpler exploit). */
int g_client_fd = -1;

/*
 * ATTACKER TARGET -- never invoked by normal control flow.
 * Redirects stdin/stdout/stderr of a /bin/sh to the client socket, giving the
 * remote attacker an interactive shell on this server.
 */
void give_shell(void) {
    dup2(g_client_fd, 0);
    dup2(g_client_fd, 1);
    dup2(g_client_fd, 2);
    execl("/bin/sh", "sh", "-i", (char *)NULL);
    _exit(0);
}

/* Reads the client request into an undersized stack buffer. THE BUG. */
void handle_request(int client_fd) {
    char buffer[64];                 /* fixed-size stack buffer            */
    char request[2048];              /* large staging area                 */

    ssize_t n = recv(client_fd, request, sizeof(request) - 1, 0);
    if (n <= 0) return;

    /* No length check: copies the whole request into a 64-byte buffer. */
    memcpy(buffer, request, n);      /* CWE-121: remote stack overflow     */

    /* Echo back so the service looks "normal". */
    dprintf(client_fd, "Server received: %.*s\n", (int)n, buffer);
}

int main(void) {
    signal(SIGCHLD, SIG_IGN);        /* reap children automatically        */

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(srv, 8);
    printf("[server] listening on 0.0.0.0:%d\n", PORT);
    fflush(stdout);

    for (;;) {
        int client = accept(srv, NULL, NULL);
        if (client < 0) continue;
        if (fork() == 0) {           /* child handles the client            */
            close(srv);
            g_client_fd = client;
            handle_request(client);
            close(client);
            _exit(0);
        }
        close(client);               /* parent keeps listening              */
    }
    return 0;
}
