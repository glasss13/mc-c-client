#pragma once

#ifdef _WIN32
#include <WinSock2.h>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib")  // Winsock Library
#define close(x) closesocket(x)
#else
typedef unsigned int SOCKET;
#include <arpa/inet.h>
#include <unistd.h>
#endif

/**
 * Create a socket and connect it to address
 * returns -1 if failed.
 */
SOCKET create_socket_connect(const char ip[], const int port);
