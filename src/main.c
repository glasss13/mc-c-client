#include <openssl/rand.h>
#include <pthread.h>
#include <stdbool.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include "bot.h"
#include "compression.h"
#include "encryption.h"
#include "network.h"
#include "packet.h"
#include "protocol_string.h"
#include "session.h"
#include "socket.h"
#include "string.h"
#include "varint2.h"

#define NEXT_ITERATION()                              \
    last_iteration_end_pos += server_response_length; \
    continue;

void* channel_read(void* thread) {
    printf("Listening thread starting...\n");

    uint8_t* server_response = malloc(8192);
    size_t server_response_length = 0;

    VARINT length_varint;
    bool receiving_length_varint = true;
    size_t length_varint_start_pos = 0;

    size_t last_iteration_end_pos = -1;

    bool receiving_packet_data = false;
    size_t packet_data_length = 0;

    int packet_length = 0;

    for (;;) {
        size_t current_iteration_pos = last_iteration_end_pos + 1;
        uint8_t* current_iteration_buffer_pos = server_response + current_iteration_pos;

        server_response_length = recv(bot.conn.fd, current_iteration_buffer_pos, 8192 - current_iteration_pos, 0);

        if (bot.conn.encryption_enabled) {
            aes_decrypt(bot.conn.decryption_ctx, current_iteration_buffer_pos, current_iteration_buffer_pos, server_response_length);
        }

        if (receiving_length_varint) {
            // if this fails that means we havent received the full varint yet
            if (varint_sizeof_buffer_as_varint(server_response) == -1) {
                NEXT_ITERATION();
            }

            length_varint = varint_buffer_as_varint(server_response);
            packet_data_length = varint_to_int(&length_varint);
            receiving_length_varint = false;
            receiving_packet_data = true;
        }

        if (receiving_packet_data) {
            // we havent received all the bytes yet
            if (server_response_length - length_varint.size < packet_data_length) {
                NEXT_ITERATION();
            }
            printf("varint size: %zu\n", length_varint.size);
            printf("data size: %zu\n", packet_data_length);
        }
        // continue;

        // if (bot.conn.compthresh > -1) {
        //     printf("decompressing...\n");  // decompress
        //     int data_length = decode_varint(
        //         bot.conn.inbuffer);  // Length of uncompressed (Packet ID +
        //                              // Data) or 0 if compression isn't enabled
        //     if (data_length ==
        //         0) {  // if compression isn't enabled, get rid of data length
        //               // varint stored in buffer and then continue as normal
        //         memcpy(bot.conn.inbuffer,
        //                bot.conn.inbuffer + ivarint_size(data_length),
        //                sizeof(bot.conn.inbuffer) - ivarint_size(data_length));
        //     } else {
        //         zdecompress(packet_length - ivarint_size(data_length),
        //                     bot.conn.inbuffer + ivarint_size(data_length),
        //                     data_length, bot.conn.inbuffer);
        //     }
        // }
        printf("HERE\n");
        struct Packet in_packet = receive_packet(server_response, &bot.conn);
        printf("[Received Packet] State: %i, Length: %zu, Id: 0x%02X\n", bot.conn.state, packet_data_length, in_packet.id);
        process_packet(&in_packet, &bot.conn);
        return NULL;
    }

    close(bot.conn.fd);
    pthread_exit(NULL);
}

int main(int argc, char* argv[]) {
    // let this be hostname and just ipv4 address
    char* ip = argv[1];
    // probably should make this some sort of default
    int port = atoi(argv[2]);
    char* username = argv[3];
    char* password = argv[4];

    printf("ip: %s port: %i username: %s password %s\n", ip, port, username,
           password);
    // maybe something for storing accessTokens between runs?
    // also only make this run if an encryption request is sent
    // bot.session = auth_client(username, password);
    printf("here\n");
    bot.conn.encryption_enabled = 0;

    bot.conn.fd = create_socket_connect(ip, port);
    if (bot.conn.fd == -1) {
        perror("Error while connecting");
        return -1;
    }

    bot.conn.state = HANDSHAKING;
    bot.conn.compthresh = -1;

    pthread_t channel_read_thread;
    pthread_create(&channel_read_thread, NULL, channel_read, 0);

    struct Packet handshake_packet = {
        HANDSHAKE, .data.C00Handshake = {47, ip, port, LOGIN}};
    send_packet(&handshake_packet, &bot.conn);

    // struct Packet login_packet = {LOGIN_START, .data.C00PacketLoginStart = {bot.session.name}};
    struct Packet login_packet = {LOGIN_START, .data.C00PacketLoginStart = {"Yourmother"}};
    send_packet(&login_packet, &bot.conn);

    pthread_join(channel_read_thread, NULL);
    return 0;
}
