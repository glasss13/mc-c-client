#pragma once

#include <openssl/ssl.h>

#include "cJSON.h"
#include "socket.h"

enum ConnectionState { HANDSHAKING = -1, PLAY = 0, STATUS = 1, LOGIN = 2 };

struct Connection {
  SOCKET fd;
  enum ConnectionState state;
  char inbuffer[40000];
  char outbuffer[20000];
  unsigned char* shared_secret;
  int encryption_enabled;
  EVP_CIPHER_CTX* encryption_ctx;
  EVP_CIPHER_CTX* decryption_ctx;
  int compthresh;
};

cJSON* post_req(const char* host, const char* path, const char* body);

struct Session auth_client(const char* username, const char* password);

cJSON* join_server(const char* accessToken, const char* uuid, const char* hash);
