file(GLOB SOURCES "*.cpp")

add_library(homelink_common STATIC ${SOURCES})

target_include_directories(homelink_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})