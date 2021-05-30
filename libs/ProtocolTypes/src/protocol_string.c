#include "protocol_string.h"
#include "varint.h"
#include <stdlib.h>
#include <string.h>

PROTOCOL_STRING protocol_string_from_c_string(char const* const string) {
    size_t string_length = strlen(string);
    PROTOCOL_STRING return_string;

    return_string.text = malloc(string_length);
    if (return_string.text == NULL) {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }
    return_string.length = varint_from_int(string_length);
    return_string.size = return_string.length.size + string_length;

    memcpy(return_string.text, string, string_length);

    return return_string;
}

char* protocol_string_as_byte_buf(PROTOCOL_STRING const* const string) {
    char* return_buf = malloc(string->size);
    if (return_buf == NULL) {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    memcpy(return_buf, string->length.data, string->length.size);
    memcpy(return_buf + string->length.size, string->text, string->size);

    return return_buf;
}

void protocol_string_free(PROTOCOL_STRING* const string) {
    varint_free(&string->length);
    free(string->text);
}
