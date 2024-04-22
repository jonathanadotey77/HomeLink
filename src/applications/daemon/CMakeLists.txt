find_library(homelink_common HINTS ${CMAKE_BINARY_DIR})

add_executable(homelink_daemon homelink_daemon.c)
target_include_directories(homelink_daemon PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../lib/common)
target_link_libraries(homelink_daemon PRIVATE homelink_common homelink_client)
set_target_properties(homelink_daemon PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/applications)
