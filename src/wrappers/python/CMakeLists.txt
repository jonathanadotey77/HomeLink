file(GLOB SOURCES "*.c")

add_library(homelink_python SHARED ${SOURCES})

find_package(PythonLibs REQUIRED)

set_target_properties(homelink_python PROPERTIES
    LANGUAGE C
    OUTPUT_NAME "_homelink_python_c_extension"
    VERSION 1.0
)

target_include_directories(homelink_python PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/c/common
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/c/client
    ${PYTHON_INCLUDE_DIRS})

target_link_libraries(homelink_python PRIVATE homelink_common homelink_client ${PYTHON_LIBRARIES})