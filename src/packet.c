#include "packet.h"

#ifndef _WIN32
#include <arpa/inet.h>
#include <stdlib.h>
#endif

#include "bot.h"
#include "compression.h"
#include "encryption.h"
#include "p_string.h"
#include "socket.h"
#include "varint.h"
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <string.h>
#include <time.h>

// write to raw buffer from packet data
int write_C00Handshake(struct Packet* packet, char* buffer) {
    varint protocol = encode_varint(packet->data.C00Handshake.protocol);
    p_string addr = encode_string(packet->data.C00Handshake.addr);
    unsigned short port = packet->data.C00Handshake.port;
    varint state = encode_varint(packet->data.C00Handshake.state);

    int length = varint_size(protocol) + pstrsize(addr) + sizeof(port) +
                 varint_size(state) + sizeof(packet->id);
    varint vlength = encode_varint(length);

    void* temp_offset = buffer;
    memcpy(temp_offset, vlength, varint_size(vlength));
    temp_offset += varint_size(vlength);

    memcpy(temp_offset, &packet->id, sizeof(packet->id));
    temp_offset += sizeof(packet->id);

    memcpy(temp_offset, protocol, varint_size(protocol));
    temp_offset += varint_size(protocol);

    memcpy(temp_offset, addr, pstrsize(addr));
    temp_offset += pstrsize(addr);

    memcpy(temp_offset, &port, sizeof(port));
    temp_offset += sizeof(port);

    memcpy(temp_offset, state, varint_size(state));

    free(vlength);
    free(protocol);
    free(addr);
    free(state);

    return length;
}

int write_C00PacketLoginStart(struct Packet* packet, char* buffer) {
    p_string name = encode_string(packet->data.C00PacketLoginStart.name);

    int length = pstrsize(name) + sizeof(packet->id);
    varint vlength = encode_varint(length);

    void* temp_offset = buffer;
    memcpy(temp_offset, vlength, varint_size(vlength));
    temp_offset += varint_size(vlength);

    memcpy(temp_offset, &packet->id, sizeof(packet->id));
    temp_offset += sizeof(packet->id);

    memcpy(temp_offset, name, pstrsize(name));

    free(vlength);
    free(name);

    return length;
}

int write_C01PacketEncryptionResponse(struct Packet* packet, char* buffer) {
    varint secret_len =
        encode_varint(packet->data.C01PacketEncryptionResponse.ss_len);
    varint verify_len =
        encode_varint(packet->data.C01PacketEncryptionResponse.vt_len);

    int length = varint_size(secret_len) + varint_size(verify_len) +
                 packet->data.C01PacketEncryptionResponse.ss_len +
                 packet->data.C01PacketEncryptionResponse.vt_len +
                 sizeof(packet->id);
    varint vlength = encode_varint(length);

    void* temp_offset = buffer;
    memcpy(temp_offset, vlength, varint_size(vlength));
    temp_offset += varint_size(vlength);

    memcpy(temp_offset, &packet->id, sizeof(packet->id));
    temp_offset += sizeof(packet->id);

    memcpy(temp_offset, secret_len, varint_size(secret_len));
    temp_offset += varint_size(secret_len);

    memcpy(temp_offset, packet->data.C01PacketEncryptionResponse.ss,
           packet->data.C01PacketEncryptionResponse.ss_len);
    temp_offset += packet->data.C01PacketEncryptionResponse.ss_len;

    memcpy(temp_offset, verify_len, varint_size(verify_len));
    temp_offset += varint_size(verify_len);

    memcpy(temp_offset, packet->data.C01PacketEncryptionResponse.vt,
           packet->data.C01PacketEncryptionResponse.vt_len);

    free(vlength);
    free(secret_len);
    free(verify_len);

    return length;
}

int write_C01PacketChatMessage(struct Packet* packet, char* buffer) {
    p_string message = encode_string(packet->data.C00PacketChatMessage.message);

    int length = pstrsize(message) + sizeof(packet->id);
    varint vlength = encode_varint(length);

    void* temp_offset = buffer;
    memcpy(temp_offset, vlength, varint_size(vlength));
    temp_offset += varint_size(vlength);

    memcpy(temp_offset, &packet->id, sizeof(packet->id));
    temp_offset += sizeof(packet->id);

    memcpy(temp_offset, message, pstrsize(message));

    free(vlength);
    free(message);

    return length;
}

void send_packet(struct Packet* packet, struct Connection* conn) {
    int packet_length;

    if (conn->state == HANDSHAKING) {
        if (packet->id != HANDSHAKE) {
            fprintf(stderr, "Invalid ID of %c for handshaking state.\n",
                    packet->id);
            exit(-1);
        }
        packet_length = write_C00Handshake(packet, conn->outbuffer);
        conn->state = packet->data.C00Handshake.state;

    } else if (conn->state == PLAY) {
        switch (packet->id) {
            case CHAT_MESSAGE_S:
                packet_length =
                    write_C01PacketChatMessage(packet, conn->outbuffer);
                break;
            default:
                fprintf(stderr, "Invalid ID of %c for play state.\n",
                        packet->id);
                exit(-1);
        }

    } else if (conn->state == STATUS) {
        switch (packet->id) {
            default:
                fprintf(stderr, "Invalid ID of %c for status state.\n",
                        packet->id);
                exit(-1);
        }

    } else if (conn->state == LOGIN) {
        switch (packet->id) {
            case LOGIN_START:
                packet_length =
                    write_C00PacketLoginStart(packet, conn->outbuffer);
                break;
            case ENCRYPTION_RESPONSE:
                packet_length =
                    write_C01PacketEncryptionResponse(packet, conn->outbuffer);
                break;
            default:
                fprintf(stderr, "Invalid ID of %c for login state.\n",
                        packet->id);
                exit(-1);
        }
    } else {
        fprintf(stderr, "Invalid state %c\n", conn->state);
        exit(-1);
    }

    if (conn->compthresh > -1) {  // compression is enabled
        int data_length;
        if (packet_length < conn->compthresh) {  // don't compress this packet
            data_length = 0;
            packet_length += ivarint_size(data_length);

            varint vdata_length = encode_varint(data_length);
            // change format packet_length | data to packet_length | data_length
            // | data. memmove shifts over data to accomadate the
            // comp_data_length
            memmove(conn->outbuffer + ivarint_size(data_length) +
                        ivarint_size(packet_length),
                    conn->outbuffer + ivarint_size(packet_length),
                    sizeof(conn->outbuffer) - ivarint_size(packet_length));
            // copy data_length to the open memory given by the memmove
            memcpy(conn->outbuffer + ivarint_size(packet_length), vdata_length,
                   varint_size(vdata_length));
            free(vdata_length);

            varint vpacket_length = encode_varint(packet_length);
            // overwrite length
            memcpy(conn->outbuffer, vpacket_length,
                   varint_size(vpacket_length));
            free(vpacket_length);

        } else {  // compress data
            // Length of uncompressed (Packet ID + Data) or 0
            data_length = packet_length;
            char temp_out[sizeof(conn->outbuffer)];

            // length of compressed id and data
            int compressed_length = zcompress(
                packet_length, conn->outbuffer + ivarint_size(packet_length),
                sizeof(conn->outbuffer) - ivarint_size(packet_length),
                temp_out + ivarint_size(packet_length));
            memcpy(conn->outbuffer + ivarint_size(packet_length),
                   temp_out + ivarint_size(packet_length),
                   sizeof(temp_out) - ivarint_size(packet_length));
            // 	Length of Data Length + compressed length of (Packet ID + Data)
            packet_length = ivarint_size(data_length) + compressed_length;

            // varint of compressed id and data length
            varint vpacket_length = encode_varint(packet_length);

            memmove(conn->outbuffer + ivarint_size(packet_length),
                    conn->outbuffer,
                    sizeof(conn->outbuffer) - ivarint_size(packet_length));

            memcpy(conn->outbuffer, vpacket_length,
                   varint_size(vpacket_length));

            free(vpacket_length);
        }
    }

    if (conn->encryption_enabled) {
        aes_encrypt(conn->encryption_ctx, (unsigned char*)conn->outbuffer,
                    (unsigned char*)conn->outbuffer,
                    packet_length + ivarint_size(packet_length));
    }

    // send data
    send(conn->fd, conn->outbuffer, packet_length + ivarint_size(packet_length),
         0);
}

// read raw buffer data and write to packet
void read_S01PacketEncryptionRequest(struct Packet* packet, char* buffer) {
    void* temp_offset = buffer;

    packet->data.S01PacketEncryptionRequest.server_id =
        decode_string(temp_offset);
    temp_offset += pstrsize(buffer);

    packet->data.S01PacketEncryptionRequest.pub_key_length =
        decode_varint(temp_offset);
    temp_offset += varint_size(temp_offset);

    packet->data.S01PacketEncryptionRequest.pub_key = temp_offset;
    temp_offset += packet->data.S01PacketEncryptionRequest.pub_key_length;

    packet->data.S01PacketEncryptionRequest.verify_token_length =
        decode_varint(temp_offset);
    temp_offset += varint_size(temp_offset);

    packet->data.S01PacketEncryptionRequest.verify_token = (char*)temp_offset;
}

void read_S02LoginSuccess(struct Packet* packet, char* buffer) {
    void* temp_offset = buffer;

    packet->data.S02PacketLoginSuccess.uuid = decode_string(temp_offset);
    temp_offset += pstrsize(buffer);

    packet->data.S02PacketLoginSuccess.name = decode_string(temp_offset);
}

void read_S03PacketSetCompression(struct Packet* packet, char* buffer) {
    void* temp_offset = buffer;

    packet->data.S03PacketSetCompression.threshold = decode_varint(temp_offset);
}

// turn raw buffer data into Packet struct
struct Packet receive_packet(char* buffer, struct Connection* conn) {
    struct Packet packet;
    packet.id = buffer[0];

    if (conn->state == HANDSHAKING) {
        printf(
            "Something went wrong. Likely forgot to change state away from "
            "handshake.");
    } else if (conn->state == PLAY) {
    } else if (conn->state == STATUS) {
    } else if (conn->state == LOGIN) {
        switch (packet.id) {
            case ENCRYPTION_REQUEST:
                read_S01PacketEncryptionRequest(&packet, buffer + 1);
                break;
            case LOGIN_SUCCESS:
                read_S02LoginSuccess(&packet, buffer + 1);
                break;
            case SET_COMPRESSION:
                read_S03PacketSetCompression(&packet, buffer + 1);
                break;
        }
    } else
        return packet;
    return packet;
}

void twosComp(unsigned char* buffer, size_t len) {
    int carry = 1;
    unsigned char value;
    unsigned char newByte;
    for (int i = len - 1; i >= 0; i--) {
        value = buffer[i];

        newByte = ~value & 0xff;

        if (carry) {
            carry = newByte == 0xff;
            buffer[i] = newByte + 1;
        } else {
            buffer[i] = newByte;
        }
    }
}

void process_S01PacketEncryptionRequest(struct Packet* packet,
                                        struct Connection* conn) {
    // generate shared secret
    unsigned char shared_key[16];
    RAND_priv_bytes(shared_key, sizeof(shared_key));

    // calculate hash
    unsigned char serv_hash[SHA_DIGEST_LENGTH];
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, shared_key, sizeof(shared_key));
    SHA1_Update(&ctx, packet->data.S01PacketEncryptionRequest.pub_key,
                packet->data.S01PacketEncryptionRequest.pub_key_length);
    SHA1_Final(serv_hash, &ctx);

    int isNeg = serv_hash[0] > 127;
    if (isNeg) twosComp(serv_hash, sizeof(serv_hash));

    char serv_hash_str[SHA_DIGEST_LENGTH * 2 + 2];
    serv_hash_str[0] = '-';
    for (int i = 0; i < sizeof(serv_hash); i++) {
        sprintf((char*)&serv_hash_str[i * 2 + 1], "%02X", serv_hash[i]);
    }

    cJSON* ret_json;
    if (isNeg) {
        ret_json = join_server(bot.session.accessToken, bot.session.uuid,
                               serv_hash_str);
    } else {
        ret_json = join_server(bot.session.accessToken, bot.session.uuid,
                               serv_hash_str + 1);
    }
    cJSON_Delete(ret_json);

    // asymmetric encryption
    RSA* pub_key = d2i_RSA_PUBKEY(
        NULL,
        (const unsigned char**)&packet->data.S01PacketEncryptionRequest.pub_key,
        packet->data.S01PacketEncryptionRequest.pub_key_length);

    char* shared_enc = malloc(RSA_size(pub_key));
    char* verify_enc = malloc(RSA_size(pub_key));

    RSA_public_encrypt(sizeof(shared_key), (const unsigned char*)shared_key,
                       (unsigned char*)shared_enc, pub_key, RSA_PKCS1_PADDING);
    RSA_public_encrypt(
        packet->data.S01PacketEncryptionRequest.verify_token_length,
        (const unsigned char*)
            packet->data.S01PacketEncryptionRequest.verify_token,
        (unsigned char*)verify_enc, pub_key, RSA_PKCS1_PADDING);

    struct Packet response_packet = {
        ENCRYPTION_RESPONSE,
        .data.C01PacketEncryptionResponse = {RSA_size(pub_key), shared_enc,
                                             RSA_size(pub_key), verify_enc}};
    send_packet(&response_packet, conn);
    enable_encryption(conn, shared_key);

    RSA_free(pub_key);
    free(shared_enc);
    free(verify_enc);
}

void process_S02PacketLoginSuccess(struct Packet* packet,
                                   struct Connection* conn) {
    conn->state = PLAY;
    bot.thePlayer.name = packet->data.S02PacketLoginSuccess.name;
    bot.thePlayer.uuid = packet->data.S02PacketLoginSuccess.uuid;
    printf("Logged in with name: %s and uuid: %s\n", bot.thePlayer.name,
           bot.thePlayer.uuid);
    usleep(50 * 1000);
    struct Packet chat_packet = {
        CHAT_MESSAGE_S, .data.C00PacketChatMessage = {"hello server!"}};
    send_packet(&chat_packet, &bot.conn);
}

void process_S03PacketSetCompression(struct Packet* packet,
                                     struct Connection* conn) {
    conn->compthresh = packet->data.S03PacketSetCompression.threshold;
}

// actually utilize the packet
void process_packet(struct Packet* packet, struct Connection* conn) {
    if (conn->state == HANDSHAKING) {
        printf(
            "Something went wrong. Likely forgot to change state away from "
            "handshake.");
    } else if (conn->state == PLAY) {
    } else if (conn->state == STATUS) {
    } else if (conn->state == LOGIN) {
        switch (packet->id) {
            case ENCRYPTION_REQUEST:
                process_S01PacketEncryptionRequest(packet, conn);
                break;
            case LOGIN_SUCCESS:
                process_S02PacketLoginSuccess(packet, conn);
                break;
            case SET_COMPRESSION:
                process_S03PacketSetCompression(packet, conn);
                break;
        }
    }

    return;
}
