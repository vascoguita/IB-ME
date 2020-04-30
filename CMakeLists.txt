cmake_minimum_required(VERSION 3.15)
project(IBME)

file(GLOB SOURCES src/* include/*)

add_library(ibme ${SOURCES})

target_include_directories(ibme PUBLIC include)
target_link_libraries(ibme pbc gmp crypto)

add_subdirectory(demo)