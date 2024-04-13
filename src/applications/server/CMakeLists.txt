file(GLOB SOURCES "*.cpp")

find_library(homelink_common HINTS ${CMAKE_BINARY_DIR})

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

add_executable(homelink_server ${SOURCES})
target_include_directories(homelink_server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/common ${SQLITE3_INCLUDE_DIRS})
target_link_libraries(homelink_server PRIVATE homelink_common OpenSSL::Crypto ${CMAKE_THREAD_LIBS_INIT} sqlite3)

set_target_properties(homelink_server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/applications)