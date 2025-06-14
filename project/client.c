#include "libsecurity/libsecurity.h"
#include "tlv.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NONCE_TYPE 0x01
#define PUBLIC_KEY_TYPE 0x02
#define CLIENT_HELLO_TYPE 0x10

void die(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void send_all(int sockfd, const uint8_t* buf, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = send(sockfd, buf + total_sent, len - total_sent, 0);
        if (sent <= 0) die("send");
        total_sent += sent;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: ./client <hostname> <port>\n");
        exit(EXIT_FAILURE);
    }

    const char* hostname = argv[1];
    const char* port = argv[2];

    // === Create TCP socket and connect ===
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, port, &hints, &res) != 0) die("getaddrinfo");

    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) die("socket");

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) die("connect");
    freeaddrinfo(res);

    // === Build Client Hello ===
    uint8_t nonce[32];
    if (!RAND_bytes(nonce, sizeof(nonce))) die("RAND_bytes");

    Key* my_key = generate_key();
    size_t pubkey_len;
    uint8_t* pubkey = get_public_key_bytes(my_key, &pubkey_len);

    uint8_t *nonce_tlv, *pubkey_tlv, *client_hello;
    size_t nonce_tlv_len, pubkey_tlv_len, client_hello_len;

    tlv_create(NONCE_TYPE, nonce, sizeof(nonce), &nonce_tlv, &nonce_tlv_len);
    tlv_create(PUBLIC_KEY_TYPE, pubkey, pubkey_len, &pubkey_tlv, &pubkey_tlv_len);

    size_t inner_len = nonce_tlv_len + pubkey_tlv_len;
    uint8_t* inner = malloc(inner_len);
    memcpy(inner, nonce_tlv, nonce_tlv_len);
    memcpy(inner + nonce_tlv_len, pubkey_tlv, pubkey_tlv_len);

    tlv_create(CLIENT_HELLO_TYPE, inner, inner_len, &client_hello, &client_hello_len);

    // === Send Client Hello ===
    send_all(sockfd, client_hello, client_hello_len);
    printf("Client Hello sent (%lu bytes)\n", client_hello_len);

    // Clean up
    free(nonce_tlv);
    free(pubkey_tlv);
    free(inner);
    free(client_hello);
    free(pubkey);
    close(sockfd);

    return 0;
}
