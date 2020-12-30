#include "../include/socket.h"

SOCKET create_socket_connect(const char ip[], const int port) {

#ifdef _WIN32
    // random windows init stuff idk
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        exit(1);
    }
#endif

    struct sockaddr_in serv_addr;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr(ip);

    SOCKET socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) return -1;

    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &(char){1}, sizeof(int)) == -1) return -1;

    if (connect(socket_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) return -1;

    return socket_fd;
}
