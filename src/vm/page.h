#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <stdint.h>
#include <hash.h>
#include <stdbool.h>

struct sup_page_table_entry
{
  void *addr; /* Virtual address. */
  uint64_t access_time; /* Lastest time the page is accessed. Used for LRU. */
  struct hash_elem hash_elem; /* Hash table element. */
  int swap_index; /* Index of the beginning sector in swap file. */
  bool from_file; /* */
  
};

#endif /* vm/page.h */
