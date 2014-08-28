#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <netinet/in.h>
#include <err.h>
#include <sysexits.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>

#include "uthash.h"

#if defined(__APPLE__)
#  define COMMON_DIGEST_FOR_OPENSSL
#  include <CommonCrypto/CommonDigest.h>
#  define SHA CC_SHA1
#else
#  include <openssl/md5.h>
#endif

#define BUF_LEN 4096
#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 9876
#define LISTEN_BACKLOG  24
#define LISTEN_QUEUE    24

void create(char *, char *);
void extract();
void print_hash(char, char *);
void term(int);

typedef struct cache_st {
    char hash[SHA_DIGEST_LENGTH + 1];
    char data[BUF_LEN + 1];
    uint16_t len;
    UT_hash_handle hh;
} cache_t;

typedef enum cmd_en {
    CMD_NEW,
    CMD_SEND,
    CMD_ACK,
} cmd_e;

typedef struct client_conn_st {
    int sock;
    struct in_addr addr;
} client_conn_t;

cache_t *cache = NULL;
bool extract_mode = false;
bool create_mode = false;

int
main(int argc, char *argv[])
{
    int ch;
    char *fn;
    va_list args;

    while ((ch = getopt(argc, argv, "cxvf:")) != EOF) {
        switch (ch) {
            case 'f':
                fn = strdup(optarg);
                break;

            case 'c':
                create_mode = true;
                break;

            case 'x':
                extract_mode = true;
                break;
        }
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = term;
    sigaction(SIGINT, &action, NULL);

    FILE *fp = fopen("/tmp/cache", "r");
    cache_t t;
    while (!feof(fp)) {
        memset(&t, 0, sizeof(cache_t));
        int n = fread(&t, sizeof(cache_t), 1, fp);
        if (n > 0) {
            cache_t *s = malloc(sizeof(cache_t));
            memcpy(s->hash, &t.hash, SHA_DIGEST_LENGTH + 1);
            memcpy(s->data, &t.data, BUF_LEN + 1);
            s->len = t.len;
            HASH_ADD_STR(cache, hash, s);
        }
    }
    fclose(fp);

    if (create_mode) {
        create(argv[optind], fn);
    }

    if (extract_mode) {
        extract();
    }

    return 0;
}

void
create(char *fn, char *name)
{
    SHA_CTX ctx;
    char input[BUF_LEN + 1];
    unsigned char hash[SHA_DIGEST_LENGTH];
    struct sockaddr_in serv;
    int sock;
    size_t sent = 0;

    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
        err(EX_UNAVAILABLE, "unable to create socket");

    memset(&serv, 0, sizeof(struct sockaddr_in));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(SERVER_PORT);
    serv.sin_addr.s_addr = inet_addr(SERVER_HOST);

    connect(sock, (struct sockaddr *)&serv, sizeof(serv));

    FILE *in = fopen(fn, "r");

    uint8_t cmd;
    uint16_t len;

    cmd = CMD_NEW;
    send(sock, &cmd, sizeof(uint8_t), 0);

    len = strlen(name);
    send(sock, &len, sizeof(uint16_t), 0);
    send(sock, name, len, 0);

    while (!feof(in)) {
        memset(&input, 0, BUF_LEN + 1);
        int n = fread(&input, 1, BUF_LEN, in);
        if (n > 0) {
            SHA1_Init(&ctx);
            SHA1_Update(&ctx, input, strlen(input));
            SHA1_Final(hash, &ctx);
            cmd = CMD_SEND;

            send(sock, &cmd, sizeof(uint8_t), 0);
            sent += sizeof(uint8_t);

            send(sock, hash, SHA_DIGEST_LENGTH, 0);
            sent += SHA_DIGEST_LENGTH;

            recv(sock, &cmd, sizeof(uint8_t), 0);

            switch ((cmd_e)cmd) {
                case CMD_SEND:
                    cmd = CMD_SEND;
                    len = n;

                    send(sock, &len, sizeof(uint16_t), 0);
                    sent += sizeof(uint16_t);

                    send(sock, input, n, 0);
                    sent += n;

                    recv(sock, &cmd, sizeof(uint8_t), 0);
                    break;

                case CMD_ACK:
                    break;

                case CMD_NEW:
                    break;
            }
        }
    }

    printf("sent %lu bytes\n", sent);
    close(sock);
}

void
extract()
{
    cache_t *s;
    struct kevent ke;
    int sock, error, kq;
    struct sockaddr_in serv;
    FILE *fp = NULL;
    char *fn = NULL;

    memset(&ke, 0, sizeof(struct kevent));

    // init kqueue
    if ((kq = kqueue()) == -1)
        err(EX_UNAVAILABLE, "kqueue");

    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
        err(EX_UNAVAILABLE, "unable to create socket");

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&error,
                sizeof(error)) == -1)
        warn("setsockopt");

    memset(&serv, 0, sizeof(struct sockaddr_in));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(SERVER_PORT);
    serv.sin_addr.s_addr = inet_addr(SERVER_HOST);

    if (bind(sock, (struct sockaddr *)&serv, sizeof(serv)) == -1)
        err(EX_UNAVAILABLE, "bind");

    if (listen(sock, LISTEN_BACKLOG) == -1)
        err(EX_UNAVAILABLE, "listen");

    EV_SET(&ke, sock, EVFILT_READ, EV_ADD, 0, LISTEN_BACKLOG, NULL);

    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000 * 1000 * 100;

    if (kevent(kq, &ke, 1, NULL, 0, &ts) == -1)
        err(EX_UNAVAILABLE, "set update timeout kevent");

    client_conn_t conn;

    while (true) {
        memset(&ke, 0, sizeof(ke));
        if (kevent(kq, NULL, 0, &ke, 1, NULL) <= 0) {
            usleep(5000);
            continue;
        }

        if (ke.ident == (uintptr_t)sock) {
            // client connection
            int cl_sock;
            struct sockaddr_in c;
            socklen_t len;

            if ((cl_sock = accept(sock, (struct sockaddr *)&c, &len)) == -1)
                err(EX_UNAVAILABLE, "accept");

            // init client
            conn.sock = cl_sock;
            memcpy(&conn.addr, &c.sin_addr, sizeof(c.sin_addr));

            // listen to the client socket
            EV_SET(&ke, cl_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
            if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1)
                err(EX_UNAVAILABLE, "kevent add user");

        } else if (ke.ident == conn.sock) {
            uint8_t cmd;
            uint16_t len;
            char hash[SHA_DIGEST_LENGTH + 1];

            int n = read(conn.sock, &cmd, sizeof(uint8_t));

            if (n == 0) {
                EV_SET(&ke, conn.sock, EVFILT_READ, EV_DELETE, 0, 0, NULL);
                if (kevent(kq, &ke, 1, 0, 0, NULL) == -1)
                    err(EX_UNAVAILABLE, "disconnect user");

                if (fp)
                    fclose(fp);

                if (fn)
                    free(fn);

            } else {
                if ((cmd_e)cmd == CMD_NEW) {
                    recv(conn.sock, &len, sizeof(uint16_t), 0);

                    fn = malloc(len);
                    recv(conn.sock, fn, len, 0);
                    fprintf(stderr, "> %s\n", fn);
                    fp = fopen(fn, "w");

                    recv(conn.sock, &cmd, sizeof(uint8_t), 0);
                }

                recv(conn.sock, &hash, SHA_DIGEST_LENGTH, 0);
                hash[SHA_DIGEST_LENGTH] = 0;

                HASH_FIND_STR(cache, hash, s);

                if (s != NULL) {
                    cmd = CMD_ACK;
                    send(conn.sock, &cmd, sizeof(uint8_t), 0);
                    fwrite(s->data, 1, s->len, fp);
                } else {
                    cmd = CMD_SEND;
                    send(conn.sock, &cmd, sizeof(uint8_t), 0);

                    recv(conn.sock, &len, sizeof(uint16_t), 0);

                    char data[len];
                    recv(conn.sock, data, len, 0);
                    fwrite(data, 1, len, fp);

                    cache_t *m = malloc(sizeof(cache_t));

                    memcpy(&m->hash, hash, SHA_DIGEST_LENGTH);
                    m->hash[SHA_DIGEST_LENGTH] = 0;

                    memcpy(&m->data, &data, len);
                    m->data[BUF_LEN] = 0;
                    m->len = len;

                    HASH_ADD_STR(cache, hash, m);

                    cmd = CMD_ACK;
                    send(conn.sock, &cmd, sizeof(uint8_t), 0);
                }
            }
        }
    }
}

void
print_hash(char c, char *hash)
{
    printf("%c", c);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02x", (unsigned char)hash[i]);
    }
    printf("\n");
}

void
term(int signum)
{
    if (extract_mode) {
        FILE *fp = fopen("/tmp/cache", "w");
        cache_t *s, *tmp;
        HASH_ITER(hh, cache, s, tmp) {
            fwrite(s, sizeof(cache_t), 1, fp);
        }
        fclose(fp);
    }
    exit(0);
}

