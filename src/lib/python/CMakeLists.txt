add_custom_target(python
    pip3 install --upgrade --force-reinstall HomeLinkPython/
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/HomeLinkPython
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)