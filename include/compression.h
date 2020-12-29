#pragma once

unsigned long zcompress(int inlen, char* inbuffer, int outlen, char* outbuffer);

unsigned long zdecompress(int inlen, char* inbuffer, int outlen,
                          char* outbuffer);
