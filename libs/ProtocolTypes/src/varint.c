#include "varint.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

VARINT varint_from_int(int32_t to_varint) {
    uint8_t temp_varint_value[5];
    int8_t curr_byte;

    for (size_t i = 0; i < 5; i++) {
        curr_byte = to_varint & 0b01111111;

        to_varint = (uint32_t)to_varint >> 7;

        // if there are still more numbers, we need to set the highest bit to
        // indicate the number continues to the next byte
        if (to_varint != 0) {
            curr_byte |= 0b10000000;
        }
        // assemble the temporary buffer from the currently operated upon byte
        temp_varint_value[i] = curr_byte;

        // consumed every bit, varint is done encoding
        if (to_varint == 0) {
            VARINT output_varint;
            output_varint.data = malloc(i + 1);
            if (output_varint.data == NULL) {
                perror("Failed to allocate memory");
                exit(EXIT_FAILURE);
            }
            output_varint.size = i + 1;
            memcpy(output_varint.data, temp_varint_value, i + 1);

            return output_varint;
        }
    }
    assert(false);
}

void varint_set(VARINT* const varint, int32_t to_write) {
    uint8_t temp_varint_value[5];
    int8_t curr_byte;

    for (size_t i = 0; i < 5; i++) {
        curr_byte = to_write & 0b01111111;

        to_write = (uint32_t)to_write >> 7;

        if (to_write != 0) {
            curr_byte |= 0b10000000;
        }

        temp_varint_value[i] = curr_byte;

        if (to_write == 0) {
            // if the current size of the varint is not large enough, we need to
            // reallocate
            if (varint->size < i + 1) {
                varint->data = realloc(varint->data, i + 1);
                if (varint->data == NULL) {
                    perror("Failed to allocate memory");
                    exit(EXIT_FAILURE);
                }
            }

            memcpy(varint->data, temp_varint_value, i + 1);
            varint->size = i + 1;

            return;
        }
    }
}

int32_t varint_to_int(VARINT const* const varint) {
    int8_t curr_byte;
    int32_t result = 0;

    for (size_t i = 0; i < 5; i++) {
        curr_byte = varint->data[i];

        int8_t value = curr_byte & 0b01111111;

        result |= value << (7 * i);
        if ((curr_byte & 0b10000000) == 0) {
            return result;
        }
    }
    assert(false);
}

size_t sizeof_int_as_varint(int32_t num) {
    for (size_t i = 0; i < 5; i++) {
        num = (uint32_t)num >> 7;
        if (num == 0) return i + 1;
    }
    assert(false);
}

void varint_free(VARINT* const varint) { free(varint->data); }
