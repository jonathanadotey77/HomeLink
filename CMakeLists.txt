cmake_minimum_required(VERSION 3.16)

set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")

project(HomeLink VERSION 0.1 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")

execute_process(
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/config
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/daemon_files
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/login
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/filesystem
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/temp_files
)

add_subdirectory(src/applications)
add_subdirectory(src/lib/c)
# add_subdirectory(src/wrappers/python)

set_target_properties(homelink_client PROPERTIES PUBLIC_HEADER "src/lib/c/client/homelink_client.h")

install(TARGETS homelink_client
    LIBRARY DESTINATION /usr/lib
    PUBLIC_HEADER DESTINATION include/homelink)

install(TARGETS homelink_client
    LIBRARY DESTINATION /usr/local/lib/homelink
    PUBLIC_HEADER DESTINATION include/homelink)