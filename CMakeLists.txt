cmake_minimum_required(VERSION 3.5)
project(IBME)

file(GLOB SRC src/*)
file(GLOB INC include/*)

add_library(ibme STATIC ${SRC} ${INC})

target_include_directories(ibme PUBLIC include)

install(TARGETS ibme DESTINATION lib)
install(FILES ${INC} DESTINATION include/ibme)

add_subdirectory(demo)
add_subdirectory(benchmark)