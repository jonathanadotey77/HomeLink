cmake_minimum_required(VERSION 3.24)

project(HomeLink LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")

file(COPY src/applications/python DESTINATION ${CMAKE_BINARY_DIR}/applications)

add_subdirectory(src/applications)
add_subdirectory(src/lib/common)