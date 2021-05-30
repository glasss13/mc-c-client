#include "p_string.h"
#include "varint2.h"
#include <stdlib.h>
#include <string.h>

void write_string(char in_string[], p_string strbuf) {
    size_t s_len = strlen(in_string);
    size_t s_len_len = ivarint_size(s_len);

    memcpy(strbuf + s_len_len, in_string, s_len);

    varint vint_length = malloc(s_len_len);
    if (vint_length == 0) return;
    write_varint(s_len, vint_length);
    memcpy(strbuf, vint_length, s_len_len);
    free(vint_length);
}

void read_string(p_string to_read, char strbuf[]) {
    int strlength;
    // read leading varint
    read_varint(to_read, &strlength);

    size_t strlength_len = ivarint_size(strlength);

    memcpy(strbuf, to_read + strlength_len, strlength);
    // null terminate string
    strbuf[strlength] = '\x00';
}

p_string encode_string(char str[]) {
    p_string strbuf = malloc(strlen(str) + ivarint_size(strlen(str)));
    if (strbuf == NULL) {
        printf("Possible memory leak. Shutting down...");
        exit(1);
    }
    write_string(str, strbuf);
    return strbuf;
}

char* decode_string(p_string to_read) {
    // +1 for null terminator
    char* strbuf = malloc(pstrlen(to_read) + 1);
    if (strbuf == NULL) {
        printf("Possible memory leak. Shutting down...");
        exit(1);
    }
    read_string(to_read, strbuf);

    return strbuf;
}

size_t pstrlen(p_string str) {
    int strlength;
    read_varint(str, &strlength);
    return (size_t)strlength;
}

size_t pstrsize(p_string str) {
    return pstrlen(str) + ivarint_size((int)pstrlen(str));
}

size_t string_pstrsize(char str[]) {
    p_string out_string = encode_string(str);
    size_t retval = pstrsize(out_string);
    free(out_string);
    return retval;
}