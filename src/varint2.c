#include "varint2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void read_varint(varint data, int* out) {
    char current_byte;
    *out = 0;

    for (int i = 0; i < 5; i++) {
        current_byte = data[i];

        char value = (current_byte & 0b01111111);

        *out |= (value << (7 * i));
        if ((current_byte & 0b10000000) == 0) {
            return;
        }
    }
    return;
}

void write_varint(int to_varint, varint vbuffer) {
    char temp;

    for (int i = 0; i < 5; i++) {
        temp = (to_varint & 0b01111111);

        to_varint = to_varint >> 7;

        if (to_varint != 0) {
            temp |= 0b10000000;
        }
        vbuffer[i] = temp;
        if (to_varint == 0) {
            return;
        }
    }
    return;
}

size_t ivarint_size(int data) {
    for (int i = 0; i < 5; i++) {
        data = data >> 7;
        if (data == 0) return i + 1;
    }
    return 0;
}

size_t varint_size(varint data) {
    int data_int;
    read_varint(data, &data_int);
    return ivarint_size(data_int);
}

varint encode_varint(int to_varint) {
    varint encoded_int = malloc(ivarint_size(to_varint));
    if (encoded_int == NULL) {
        printf("Possible memory leak. Shutting down...");
        exit(1);
    }
    write_varint(to_varint, encoded_int);
    return encoded_int;
}

int decode_varint(varint vint) {
    int decoded_int;
    read_varint(vint, &decoded_int);
    return decoded_int;
}
