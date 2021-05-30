#pragma once
#include "varint2.h"

// representation of the encoded string per the Minecraft protocol
typedef char* p_string;

// decode contents of to_read and write to strbuf buffer
void read_string(p_string to_read, char strbuf[]);

// encode contents of in_string and write to strbuf
void write_string(char in_string[], p_string strbuf);

// encode standard null-terminated string to p_string
p_string encode_string(char str[]);

// decode p_string to standard null-terminated string
char* decode_string(p_string to_read);

// get strlen of p_string
size_t pstrlen(p_string str);

// get sizeof p_string: pstrlen plus length of length varint
size_t pstrsize(p_string str);

// get how many bytes a char[] string would be encoded as a p_string
size_t string_pstrsize(char str[]);
