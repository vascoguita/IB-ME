cmake_minimum_required(VERSION 3.15)
project(IBME)


add_subdirectory(deps)

file(GLOB IBME_SOURCES src/* include/*)

add_library(ibme ${IBME_SOURCES})

target_include_directories(ibme PUBLIC include)
target_link_libraries(ibme pbc mbedcrypto)

add_subdirectory(demo)