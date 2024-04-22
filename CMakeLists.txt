cmake_minimum_required(VERSION 3.16)

project(HomeLink LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")

execute_process(
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/daemon_files
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/login
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/filesystem
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/temp_files
)


file(COPY src/applications/client/python/homelink_client.py DESTINATION ${CMAKE_BINARY_DIR}/applications/)

add_subdirectory(src/applications)
add_subdirectory(src/lib/c)
