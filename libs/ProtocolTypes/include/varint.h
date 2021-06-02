#pragma once

#include <stdint.h>
#include <stdio.h>

// varint data type as specified by the Minecraft Protocol
// https://wiki.vg/index.php?title=Protocol&oldid=7368#VarInt_and_VarLong
typedef struct varint_st {
    uint8_t* data;
    size_t size;
} VARINT;

// Get the size an int would be if it were a varint
size_t varint_sizeof_int_as_varint(int32_t num);

// gets the size of a varint from a buffer containing a varint
// returns -1 if there is no varint or it isn't properly encoded
size_t varint_sizeof_buffer_as_varint(uint8_t const* const buffer);

// Creates a varint encoded with the value `to_varint`
// Must be freed with varint_free()
VARINT varint_from_int(int32_t to_varint);

// Creates a varint from a byte buffer and asserts it's correctly encoded
// Copies the underlying buffer's memory and must be free'd using varint_free()
VARINT varint_from_buffer(uint8_t const* const buffer);

// Similiar to varint_from_buffer, however does not do a new memory allocation
// for the underlying data, also assersts proper encoding.
// If free'd using varint_free() it will free the passed in buffer
VARINT varint_buffer_as_varint(uint8_t* const buffer);

// Modify the value of the given varint
// Changes the length as well, if necessary
void varint_set(VARINT* const varint, int32_t to_write);

// Decode the signed 32 bit value out of the varint
int32_t varint_to_int(VARINT const* const varint);

// Deallocates the provided varint
void varint_free(VARINT* varint);
