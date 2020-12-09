add_executable (demo demo.c demo.h)

target_link_libraries (demo LINK_PUBLIC ibme pbc gmp crypto)