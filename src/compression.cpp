#include "../include/compression.h"

#include <zlib.h>
#include <stdio.h>

unsigned long zcompress(int inlen, char* inbuffer, int outlen, char* outbuffer) {
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    stream.avail_in = (unsigned int)inlen;
    stream.next_in = (Bytef*)inbuffer;
    stream.avail_out = (unsigned int)outlen;
    stream.next_out = (Bytef*)outbuffer;

    deflateInit(&stream, Z_DEFLATED);
    deflate(&stream, Z_FINISH);
    deflateEnd(&stream);

    return stream.total_out;
}

unsigned long zdecompress(int inlen, char* inbuffer, int outlen, char* outbuffer) {
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    stream.avail_in = (unsigned int)inlen;
    stream.next_in = (Bytef*)inbuffer;
    stream.avail_out = (unsigned int)outlen;
    stream.next_out = (Bytef*)outbuffer;

    inflateInit(&stream);
    inflate(&stream, Z_NO_FLUSH);
    inflateEnd(&stream);

    return stream.total_out;
}
