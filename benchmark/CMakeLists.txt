add_executable (benchmark benchmark.c benchmark.h)

target_link_libraries (benchmark LINK_PUBLIC ibme pbc gmp crypto)