#include "libsecurity/libsecurity.h"
#include "tlv.h"

#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NONCE_TYPE 0x01
#define PUBLIC_KEY_TYPE 0x02
#define CLIENT_HELLO_TYPE 0x10

#define DNS_NAME_TYPE 0xA1
#define SIGNATURE_TYPE 0xA2
#define CERTIFICATE_TYPE 0xA0
#define HANDSHAKE_SIGNATURE_TYPE 0x21
#define SERVER_HELLO_TYPE 0x20

#define MAX_BUF 4096

void die(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void send_all(int sockfd, const uint8_t* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t r = send(sockfd, buf + sent, len - sent, 0);
        if (r <= 0) die("send");
        sent += r;
    }
}

ssize_t recv_all(int sockfd, uint8_t* buf, size_t maxlen) {
    ssize_t len = recv(sockfd, buf, maxlen, 0);
    if (len < 0) die("recv");
    return len;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: ./server <port>\n");
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);

    // === Setup TCP socket ===
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) die("socket");

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) die("bind");
    if (listen(sockfd, 1) < 0) die("listen");

    int clientfd = accept(sockfd, NULL, NULL);
    if (clientfd < 0) die("accept");

    // === Receive Client Hello ===
    uint8_t buf[MAX_BUF];
    ssize_t client_hello_len = recv_all(clientfd, buf, MAX_BUF);
    if (buf[0] != CLIENT_HELLO_TYPE) exit(6);  // Unexpected message

    uint8_t* client_hello = malloc(client_hello_len);
    memcpy(client_hello, buf, client_hello_len);

    // === Build Server Hello ===
    uint8_t nonce[32];
    RAND_bytes(nonce, sizeof(nonce));

    Key* priv_key = read_private_key("server_key.bin");
    size_t cert_len;
    uint8_t* cert = read_bytes_from_file("server_cert.bin", &cert_len);

    Key* ephemeral_key = generate_key();
    size_t eph_pubkey_len;
    uint8_t* eph_pubkey = get_public_key_bytes(ephemeral_key, &eph_pubkey_len);

    // Signature input: client_hello || nonce || cert || ephemeral_pubkey
    size_t sig_input_len = client_hello_len + sizeof(nonce) + cert_len + eph_pubkey_len;
    uint8_t* sig_input = malloc(sig_input_len);
    uint8_t* ptr = sig_input;
    memcpy(ptr, client_hello, client_hello_len); ptr += client_hello_len;
    memcpy(ptr, nonce, sizeof(nonce)); ptr += sizeof(nonce);
    memcpy(ptr, cert, cert_len); ptr += cert_len;
    memcpy(ptr, eph_pubkey, eph_pubkey_len);

    size_t sig_len;
    uint8_t* signature = sign(priv_key, sig_input, sig_input_len, &sig_len);

    // TLV Encoding
    uint8_t *nonce_tlv, *cert_tlv, *pubkey_tlv, *sig_tlv, *server_hello;
    size_t nonce_tlv_len, cert_tlv_len, pubkey_tlv_len, sig_tlv_len, server_hello_len;

    tlv_create(NONCE_TYPE, nonce, sizeof(nonce), &nonce_tlv, &nonce_tlv_len);
    tlv_create(CERTIFICATE_TYPE, cert, cert_len, &cert_tlv, &cert_tlv_len);
    tlv_create(PUBLIC_KEY_TYPE, eph_pubkey, eph_pubkey_len, &pubkey_tlv, &pubkey_tlv_len);
    tlv_create(HANDSHAKE_SIGNATURE_TYPE, signature, sig_len, &sig_tlv, &sig_tlv_len);

    size_t inner_len = nonce_tlv_len + cert_tlv_len + pubkey_tlv_len + sig_tlv_len;
    uint8_t* inner = malloc(inner_len);
    ptr = inner;
    memcpy(ptr, nonce_tlv, nonce_tlv_len); ptr += nonce_tlv_len;
    memcpy(ptr, cert_tlv, cert_tlv_len); ptr += cert_tlv_len;
    memcpy(ptr, pubkey_tlv, pubkey_tlv_len); ptr += pubkey_tlv_len;
    memcpy(ptr, sig_tlv, sig_tlv_len);

    tlv_create(SERVER_HELLO_TYPE, inner, inner_len, &server_hello, &server_hello_len);

    // === Send Server Hello ===
    send_all(clientfd, server_hello, server_hello_len);
    printf("Server Hello sent (%lu bytes)\n", server_hello_len);

    // Clean up
    close(clientfd);
    close(sockfd);
    free(client_hello);
    free(cert);
    free(ephemeral_key);
    free(eph_pubkey);
    free(sig_input);
    free(signature);
    free(nonce_tlv);
    free(cert_tlv);
    free(pubkey_tlv);
    free(sig_tlv);
    free(inner);
    free(server_hello);

    return 0;
}
