#include "encryption.h"
#include <openssl/ssl.h>
#include <string.h>

void enable_encryption(struct Connection* conn, unsigned char* shared_secret) {
    conn->encryption_enabled = 1;
    conn->shared_secret = shared_secret;

    conn->encryption_ctx = EVP_CIPHER_CTX_new();
    conn->decryption_ctx = EVP_CIPHER_CTX_new();

    EVP_CIPHER_CTX_init(conn->encryption_ctx);
    EVP_CIPHER_CTX_init(conn->decryption_ctx);

    EVP_EncryptInit_ex(conn->encryption_ctx, EVP_aes_128_cfb8(), NULL,
                       shared_secret, shared_secret);
    EVP_DecryptInit_ex(conn->decryption_ctx, EVP_aes_128_cfb8(), NULL,
                       shared_secret, shared_secret);
}

int aes_encrypt(EVP_CIPHER_CTX* ctx, const unsigned char* inp,
                unsigned char* outbuf, int in_len) {
    unsigned char* outbuf_off = outbuf;
    int out_len;
    for (int i = 0; i < in_len; i++) {
        EVP_EncryptUpdate(ctx, outbuf_off, &out_len, &inp[i], 1);
        outbuf_off += out_len;
    }

    return outbuf_off - outbuf;
}

int aes_decrypt(EVP_CIPHER_CTX* ctx, const unsigned char* inp,
                unsigned char* outbuf, int in_len) {
    unsigned char* outbuf_off = outbuf;
    int out_len;
    for (int i = 0; i < in_len; i++) {
        EVP_DecryptUpdate(ctx, outbuf_off, &out_len, &inp[i], 1);
        outbuf_off += out_len;
    }

    return outbuf_off - outbuf;
}
