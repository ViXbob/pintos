/* Deletes and closes file that is mapped into memory
   and verifies that it can still be read through the mapping. */

#include <string.h>
#include <syscall.h>
#include <stdio.h>
#include "tests/additional/vm/words.inc"
#include "tests/lib.h"
#include "tests/main.h"

uint32_t xor_random(void) {
    static uint32_t x = 2166136261u;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

void
test_main (void)
{
  char *actual = (char *) 0x10000000;
  int handle;
  mapid_t map;
  size_t file_size;

  /* Map file. */
  CHECK ((handle = open ("words.txt")) > 1, "open \"words.txt\"");

  CHECK ((file_size = filesize (handle)) == 1819305, "file size of is 1819305 bytes");

  CHECK ((map = mmap (handle, actual)) != MAP_FAILED, "mmap \"words.txt\"");

  /* Close file and delete it. */
  close (handle);

  int N = 30000;

  char *ptr = actual;

  for (int i = 0; i < N; i++)
    {
      uint32_t idx = xor_random () % 1819305;
      ptr[idx] = '0' + i % 10;
    }

  munmap (map);

  /* Check file. */
  check_file ("words.txt", sample, sizeof sample - 1);
}
