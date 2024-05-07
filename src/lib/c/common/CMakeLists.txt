file(GLOB SOURCES "*.c")

find_package(OpenSSL REQUIRED)
set(OPENSSL_USE_STATIC_LIBS TRUE)

add_library(homelink_common STATIC ${SOURCES})

set_target_properties(homelink_common PROPERTIES LANGUAGE C)

target_include_directories(homelink_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} OpenSSL::Crypto)
