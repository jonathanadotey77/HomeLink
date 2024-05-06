file(GLOB SOURCES "*.c")



add_library(homelink_client SHARED ${SOURCES})

find_package(OpenSSL REQUIRED)

set_target_properties(homelink_client PROPERTIES
    LANGUAGE C
    VERSION "0.1"
    OUTPUT_NAME homelink_client
DESCRIPTION "HomeLink C Client Library")

target_include_directories(homelink_client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common)

target_link_libraries(homelink_client PRIVATE homelink_common OpenSSL::Crypto)
