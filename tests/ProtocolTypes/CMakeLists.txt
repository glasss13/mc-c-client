add_executable(TestProtocolTypes testprotocol_string.c testvarint.c)

target_link_libraries(TestProtocolTypes PUBLIC ProtocolTypes)

target_include_directories(TestProtocolTypes PUBLIC ${CMAKE_SOURCE_DIR}/external/check/include)
target_link_libraries(TestProtocolTypes PUBLIC ${CMAKE_SOURCE_DIR}/external/check/lib/libcheck.a)
