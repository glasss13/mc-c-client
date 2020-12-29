#pragma once
#include "network.h"

enum PacketID {

  HANDSHAKE = 0x00,

  RESPONSE = 0x00,
  PONG = 0x01,

  REQUEST = 0x00,
  PING = 0x01,

  DISCONNECT = 0x00,
  ENCRYPTION_REQUEST = 0x01,
  LOGIN_SUCCESS = 0x02,
  SET_COMPRESSION = 0x03,

  LOGIN_START = 0x00,
  ENCRYPTION_RESPONSE = 0x01,

  KEEP_ALIVE = 0x00,
  JOIN_GAME = 0x01,
  // clientbound
  CHAT_MESSAGE_C = 0x02,
  TIME_UPDATE = 0x03,
  ENTITY_EQUIPMENT = 0x04,
  // serverbound
  CHAT_MESSAGE_S = 0x01
};

struct C00Handshake {
  int protocol;
  char* addr;
  unsigned short port;
  enum ConnectionState state;
};

struct C00PacketLoginStart {
  char* name;
};

struct C01PacketEncryptionResponse {
  int ss_len;
  char* ss;
  int vt_len;
  char* vt;
};

struct C00PacketChatMessage {
  char* message;
};

// clientbound

struct S01PacketEncryptionRequest {
  char* server_id;
  int pub_key_length;
  char* pub_key;
  int verify_token_length;
  char* verify_token;
};

struct S02PacketLoginSuccess {
  char* uuid;
  char* name;
};

struct S03PacketSetCompression {
  int threshold;
};

union packets {
  struct C00Handshake C00Handshake;
  struct C00PacketLoginStart C00PacketLoginStart;
  struct C01PacketEncryptionResponse C01PacketEncryptionResponse;
  struct C00PacketChatMessage C00PacketChatMessage;

  // clientbound

  struct S01PacketEncryptionRequest S01PacketEncryptionRequest;
  struct S02PacketLoginSuccess S02PacketLoginSuccess;
  struct S03PacketSetCompression S03PacketSetCompression;
};

struct Packet {
  char id;
  union packets data;
};

void send_packet(struct Packet* data, struct Connection* conn);

struct Packet receive_packet(char* buffer, struct Connection* conn);

void process_packet(struct Packet* packet, struct Connection* conn);