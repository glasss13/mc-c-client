#pragma once

#include "varint.h"
#include <stdint.h>
#include <stdio.h>

// String data type as specified by the Minecraft Protocol
// https://wiki.vg/index.php?title=Protocol&oldid=7368#Data_types
typedef struct protocol_string_st {
    // Length of string as varint
    VARINT length;
    // Raw UTF-8 encoded text, no null terminator
    char* text;
    // size of the whole string, includng leading varint
    size_t size;
} PROTOCOL_STRING;

// Create a protocol string from a null terminated c style string
// Must free'd using protocol_string_free()
PROTOCOL_STRING protocol_string_from_c_string(char const* const string);

// Returns a buffer containing the leading length as well as text.
// Must free'd
char* protocol_string_as_byte_buf(PROTOCOL_STRING const* const string);

// Deallocate a PROTOCOL_STRING
void protocol_string_free(PROTOCOL_STRING* const string);
