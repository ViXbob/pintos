#ifndef VM_PAGE_H
#define VM_PAGE_H
#include "debug.h"
#include "page.h"
#include "threads/synch.h"
#include <hash.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct hash sup_page_table;

struct sup_page_table_entry
{
  void *addr;            /* Virtual address. */
  uint64_t access_time;  /* Lastest time the page is accessed. Used for LRU. */
  struct hash_elem elem; /* Hash table element. */
  bool writable;         /* Whether this page can be written. */
  bool dirty;            /* Whether this page is dirty. */
  int ref_bit;           /* Clock reference bit. */
  /* Used for swap. */
  int swap_index; /* Index of the beginning sector in swap file. */
  /* Used for file load. */
  bool from_file;      /* Whethear this page is from file. */
  struct file *file;   /* File it belongs. */
  int32_t offset;      /* File offset. */
  uint32_t read_bytes; /* Number of bytes read from file. */
  uint32_t zero_bytes; /* Number of zero bytes at the end of page. */
  /* Used for mmap. */
  bool is_mmap;     /* Whether this page is mmap. */
  struct lock lock; /* Page lock. */
};

/* Initialize supplemenatry page table. */
void sup_page_table_init (sup_page_table *sup_page_table);

/* Free supplementary page table.Free all supplementary page table entries and
 * the memory allocated by sup_page_table_init. */
void sup_page_table_free (sup_page_table *sup_page_table);

/* Find entry with specific virtual address. */
struct sup_page_table_entry *sup_page_table_find_entry (sup_page_table *table,
                                                        void *target_addr);

/* Try to get a page at fault address. From file or swap or for growing stack.
 */
bool try_to_get_page (void *fault_addr, void *esp);

/* Grow stack. */
bool grow_stack (void *fault_addr);

bool lazy_load_segment (struct file *file, int32_t ofs, uint8_t *upage,
                        uint32_t read_bytes, uint32_t zero_bytes,
                        bool writable, bool is_mmap);

#endif /* vm/page.h */
