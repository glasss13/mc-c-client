#include <openssl/rand.h>
#include <pthread.h>
#ifndef _WIN32
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include "bot.h"
#include "compression.h"
#include "encryption.h"
#include "network.h"
#include "packet.h"
#include "session.h"
#include "socket.h"
#include "string.h"
#include "varint.h"

void* channel_read(void* thread) {
    printf("Listening thread starting...\n");

    for (;;) {
        int packet_length = 0;

        // read length varint
        for (int i = 0; i < 5; i++) {
            unsigned char current_byte;

            recv(bot.conn.fd, &current_byte, 1, 0);

            if (bot.conn.encryption_enabled) {
                aes_decrypt(bot.conn.decryption_ctx, &current_byte,
                            &current_byte, 1);
            }

            char value = (current_byte & 0b01111111);
            packet_length |= (value << (7 * i));
            if ((current_byte & 0b10000000) == 0) {
                break;
            }
        }

        recv(bot.conn.fd, bot.conn.inbuffer, packet_length, 0);
        if (bot.conn.encryption_enabled) {
            unsigned char temp_out[sizeof(bot.conn.inbuffer)];
            aes_decrypt(bot.conn.decryption_ctx,
                        (unsigned char*)bot.conn.inbuffer, temp_out,
                        packet_length);
            memcpy(bot.conn.inbuffer, temp_out, sizeof(temp_out));
        }

        if (bot.conn.compthresh > -1) {  // decompress
            int data_length = decode_varint(
                bot.conn.inbuffer);  // Length of uncompressed (Packet ID +
                                     // Data) or 0 if compression isn't enabled
            if (data_length ==
                0) {  // if compression isn't enabled, get rid of data length
                      // varint stored in buffer and then continue as normal
                memcpy(bot.conn.inbuffer,
                       bot.conn.inbuffer + ivarint_size(data_length),
                       sizeof(bot.conn.inbuffer) - ivarint_size(data_length));
            } else {
                zdecompress(packet_length - ivarint_size(data_length),
                            bot.conn.inbuffer + ivarint_size(data_length),
                            data_length, bot.conn.inbuffer);
            }
        }

        struct Packet in_packet = receive_packet(bot.conn.inbuffer, &bot.conn);
        printf("[Received Packet] State: %i, Length: %i, Id: 0x%02X\n",
               bot.conn.state, packet_length, in_packet.id);
        process_packet(&in_packet, &bot.conn);
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
    bot.session = auth_client(username, password);
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

    struct Packet login_packet = {
        LOGIN_START, .data.C00PacketLoginStart = {bot.session.name}};
    send_packet(&login_packet, &bot.conn);

    pthread_exit(NULL);
    return 0;
}
