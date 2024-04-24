file(GLOB SOURCES "*.c")

find_library(homelink_client HINTS ${CMAKE_BINARY_DIR})
find_library(homelink_common HINTS ${CMAKE_BINARY_DIR})

add_executable(homelink_cli ${SOURCES})
target_include_directories(homelink_cli PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../lib/client ${CMAKE_CURRENT_SOURCE_DIR}/../lib/common ${SQLITE3_INCLUDE_DIRS})
target_link_libraries(homelink_cli PRIVATE homelink_client)
set_target_properties(homelink_cli PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/applications)
