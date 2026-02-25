cmake_minimum_required(VERSION 3.16)

# Pull in MicroLink and its bundled wireguard_lwip component
set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/../microlink"
    "${CMAKE_CURRENT_SOURCE_DIR}/../microlink/components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(wol_esp32)
