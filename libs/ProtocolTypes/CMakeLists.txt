add_library(ProtocolTypes src/varint.c src/protocol_string.c)
target_include_directories(ProtocolTypes PUBLIC include)
