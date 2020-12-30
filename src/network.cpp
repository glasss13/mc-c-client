#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string.h>

#include "../include/network.h"
#include "../include/session.h"

#define BuffSize 4096

void report_and_exit(const char* msg) {
  perror(msg);
  ERR_print_errors_fp(stderr);
  exit(-1);
}

void init_ssl() {
    SSL_load_error_strings();
    SSL_library_init();
}

void cleanup_ssl(SSL_CTX* ctx, BIO* bio) {
    SSL_CTX_free(ctx);
    BIO_free_all(bio);
}

void secure_connect(const char* hostname, char* request, char* response) {
    const SSL_METHOD* method = TLS_client_method();
    if (method == NULL) report_and_exit("TLS_client_method...");

    SSL_CTX* ctx = SSL_CTX_new(method);
    if (ctx == NULL) report_and_exit("SSL_CTX_new...");

    BIO* bio = BIO_new_ssl_connect(ctx);
    if (bio == NULL) report_and_exit("BIO_new_ssl_connect...");

    SSL* ssl = NULL;
  
    BIO_get_ssl(bio, &ssl); // session
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, hostname); // prepare to connect

    if (BIO_do_connect(bio) <= 0) {
        cleanup_ssl(ctx, bio);
        report_and_exit("BIO_do_connect...");
    }

    // actually make request
    BIO_puts(bio, request);

    while (1) {
        memset(response, '\0', BuffSize);
        int n = BIO_read(bio, response, BuffSize);
        if (n < BuffSize) break;
    }

    cleanup_ssl(ctx, bio);
}

// TODO EVENTUALLY FIGURE OUT HOW TO NOT HAVE TO SPECIFY PORT NUMBER IN HOST
// Return value must be free'd using cJSON_Delete()
cJSON* post_req(const char* host, const char* path, const char* body) {
    init_ssl();

    char response[BuffSize];
    char message[BuffSize];

    const char* message_fmt = "POST %s HTTP/1.1\r\nContent-Type: application/json\r\nHost: %s\r\nContent-Length: %i\r\n\r\n%s";

    sprintf(message, message_fmt, path, host, strlen(body), body);
    secure_connect(host, message, response);
    cJSON* response_json;

    char data_sep[] = {'\r', '\n', '\r', '\n'};
    for (int i = 0; i < strlen(response); i++) {
        if (strncmp(&response[i], data_sep, sizeof(data_sep)) == 0) {
            response_json = cJSON_Parse(response + i + sizeof(data_sep));
            break;
        }
    }

    return response_json;
}

// return value must be free'd using cJSON_Delete
cJSON* join_server(const char* accessToken, const char* uuid, const char* hash) {
    const char* hostname = "sessionserver.mojang.com:443";

    cJSON* body_json = cJSON_CreateObject();

    cJSON_AddStringToObject(body_json, "accessToken", accessToken);
    cJSON_AddStringToObject(body_json, "selectedProfile", uuid);
    cJSON_AddStringToObject(body_json, "serverId", hash);

    char* body_string = cJSON_Print(body_json);
    cJSON_Delete(body_json);

    cJSON* response_json = post_req(hostname, "/session/minecraft/join", body_string);

    free(body_string);
    return response_json;
}

// struct Session auth_client(const char* username, const char* clientToken, const char* password) {
struct Session auth_client(const char* username, const char* password) {
    const char* hostname = "authserver.mojang.com:443";

    cJSON* body_json = cJSON_CreateObject();
    cJSON* agent_json = cJSON_AddObjectToObject(body_json, "agent");

    cJSON_AddStringToObject(agent_json, "name", "Minecraft");
    cJSON_AddNumberToObject(agent_json, "version", 1);
    cJSON_AddStringToObject(body_json, "username", username);
    // cJSON_AddStringToObject(body_json, "clientToken", clientToken);
    cJSON_AddStringToObject(body_json, "password", password);
    cJSON_AddBoolToObject(body_json, "requestUser", cJSON_True);

    char* body_string = cJSON_Print(body_json);
    cJSON_Delete(body_json);
    
    cJSON* response_json = post_req(hostname, "/authenticate", body_string);

    struct Session ret_session;
    
    ret_session.accessToken = cJSON_GetObjectItemCaseSensitive(response_json, "accessToken")->valuestring;

    cJSON* selectedProfile = cJSON_GetObjectItem(response_json, "selectedProfile");
    ret_session.name = cJSON_GetObjectItemCaseSensitive(selectedProfile, "name")->valuestring;
    ret_session.uuid = cJSON_GetObjectItemCaseSensitive(selectedProfile, "id")->valuestring;

    // cJSON_Delete(response_json); dont deallocate otherwise the pointers are lost
    free(body_string);
    
    return ret_session;
}
