#include <stdio.h>
#include <stdint.h> // for intptr_t
#include <stdlib.h>
#include <gmp.h>
#include "pbc_utils.h"
#include "pbc_random.h"

void pbc_init_random(void) {
  FILE *fp;
  if(!(fp = fopen("/dev/urandom", "rb"))) {
      pbc_die("could not open /dev/urandom");
  }
  pbc_random_set_file("/dev/urandom");
  fclose(fp);
}