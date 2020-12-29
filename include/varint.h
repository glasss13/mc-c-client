#pragma once
#include <stdio.h>

// representation of the encoded varint per the Minecraft protocol
typedef char* varint;

// decode contents of data and write to out buffer
void read_varint(varint data, int* out);

// encode contents of to_varint and write to vbuffer
void write_varint(int to_varint, varint vbuffer);

// get amount of bytes an int will take as a varint
size_t ivarint_size(int data);

// get the size of varint
size_t varint_size(varint data);

// encode standard int to varint
varint encode_varint(int to_varint);

// decode varint to standard int
int decode_varint(varint vint);
