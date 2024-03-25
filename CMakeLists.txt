cmake_minimum_required(VERSION 3.24)

project(HomeLink LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(src/applications)
add_subdirectory(src/lib/common)