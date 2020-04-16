add_library (ibme ibme.c ibme.h keys.c keys.h hash.c hash.h cipher.c cipher.h padding.c padding.h)

target_include_directories (ibme PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ibme pbc gmp crypto)