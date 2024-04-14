file(GLOB SOURCES "*.c")

add_library(homelink_common STATIC ${SOURCES})

set_target_properties(homelink_common PROPERTIES LANGUAGE C)

target_include_directories(homelink_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
