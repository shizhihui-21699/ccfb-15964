cmake_minimum_required(VERSION 3.16)
project(bgp_tcp_ao LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

find_package(Threads REQUIRED)

set(TCPAO_SOURCES
    src/sha1.c
    src/ao_aes_cmac.c
    src/ao_util.c
    src/ao_table.c
    src/ao_kdf.c
    src/ao_sne.c
    src/ao_codec.c
    src/ao_conn.c
    src/ao_rotation.c
    src/bgp_journal.c
    src/ao_policy.c
    src/pal/ao_linux.c
)

add_library(tcpao STATIC ${TCPAO_SOURCES})
target_include_directories(tcpao PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_definitions(tcpao PRIVATE _GNU_SOURCE)
target_link_libraries(tcpao PUBLIC Threads::Threads)

add_executable(test_tcp_ao tests/test_tcp_ao.c)
target_include_directories(test_tcp_ao PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(test_tcp_ao PRIVATE tcpao)

add_executable(bgp_ao_rollover examples/bgp_ao_rollover.c)
target_link_libraries(bgp_ao_rollover PRIVATE tcpao)

enable_testing()
add_test(NAME tcp_ao_unit_and_vectors COMMAND test_tcp_ao)
