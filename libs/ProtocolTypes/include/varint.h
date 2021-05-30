#pragma once

#include <stdint.h>
#include <stdio.h>

// varint data type as specified by the Minecraft Protocol
// https://wiki.vg/index.php?title=Protocol&oldid=7368#VarInt_and_VarLong
typedef struct varint_st {
    uint8_t* data;
    size_t size;
} VARINT;

// Creates a varint encoded with the value `to_varint`
// Must be freed with varint_free()
VARINT varint_from_int(int32_t to_varint);

// Modify the value of the given varint
// Changes the length as well, if necessary
void varint_set(VARINT* const varint, int32_t to_write);

// Decode the signed 32 bit value out of the varint
int32_t varint_to_int(VARINT const* const varint);

// Get the size an int would be if it were a varint
size_t sizeof_int_as_varint(int32_t num);

// Deallocates the provided varint
void varint_free(VARINT* varint);
