cmake_minimum_required(VERSION 3.8)

project("mc-c-client")

add_executable(mc-c-client src/main.c src/compression.c src/encryption.c src/network.c src/p_string.c src/packet.c src/socket.c src/varint.c)

# cJSON
add_subdirectory(libs/cJSON)
target_link_libraries(mc-c-client PUBLIC cJSON)

# OPENSSL
target_link_libraries(mc-c-client PUBLIC ${CMAKE_SOURCE_DIR}/external/openssl/lib/libcrypto.a)
target_link_libraries(mc-c-client PUBLIC ${CMAKE_SOURCE_DIR}/external/openssl/lib/libssl.a)
target_include_directories(mc-c-client PUBLIC external/openssl/include)

# ZLIB
target_link_libraries(mc-c-client PUBLIC ${CMAKE_SOURCE_DIR}/external/zlib/lib/libz.a)
target_include_directories(mc-c-client PUBLIC external/zlib/include)

target_include_directories(mc-c-client PUBLIC include)
