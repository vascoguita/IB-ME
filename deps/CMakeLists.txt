file(GLOB PBC_SOURCES pbc/*/*)

add_library(pbc ${PBC_SOURCES})

target_include_directories(pbc PRIVATE pbc/)
target_include_directories(pbc PUBLIC pbc/include)
target_link_libraries(pbc gmp m)