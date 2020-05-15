cmake_minimum_required(VERSION 3.15)
project(IBME)


#add_definitions(-DDEBUG)
#include_directories(${CMAKE_SOURCE_DIR}/../optee_os/out/arm/export-ta_arm64/include)

add_subdirectory(deps)

file(GLOB IBME_SOURCES ${CMAKE_SOURCE_DIR}/src/* ${CMAKE_SOURCE_DIR}/include/*)

add_library(ibme ${IBME_SOURCES})

target_include_directories(ibme PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(ibme pbc mbedcrypto)

add_subdirectory(demo)