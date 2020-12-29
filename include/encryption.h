#pragma once

#include "network.h"

void enable_encryption(struct Connection* bot, unsigned char* shared_secret);

int aes_decrypt(EVP_CIPHER_CTX* ctx, const unsigned char* inp,
                unsigned char* outbuf, int in_len);

int aes_encrypt(EVP_CIPHER_CTX* ctx, const unsigned char* inp,
                unsigned char* outbuf, int in_len);
