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
  /* Used for swap. */
  int swap_index; /* Index of the beginning sector in swap file. */
  /* Used for file load. */
  bool from_file;      /* Whethear this page is from file. */
  struct file *file;   /* File it belongs. */
  int32_t offset;      /* File offset. */
  uint32_t read_bytes; /* Number of bytes read from file. */
  uint32_t zero_bytes; /* Number of zero bytes at the end of page. */
  bool writable;       /* Whether this page can be written. */
  /* Used for mmap. */
  bool is_mmap;     /* Whether this page is mmap. */
  struct lock lock; /* Page lock. */
};

/* Hash function of supplementary page table. */
unsigned sup_page_table_hash_func (const struct hash_elem *e,
                                   void *aux UNUSED);

/* Less function of supplementary page table. */
bool sup_page_table_less_func (const struct hash_elem *a,
                               const struct hash_elem *b, void *aux UNUSED);

/* Initialize supplemenatry page table. */
void sup_page_table_init (sup_page_table *sup_page_table);

/* Allocate and initialize a supplementary page table entry. */
struct sup_page_table_entry *new_sup_page_table_entry (void *addr,
                                                       uint64_t access_time);

/* Find entry with specific virtual address. */
struct sup_page_table_entry *find_entry (sup_page_table *table,
                                         void *target_addr);

/* Try to get a page at fault address. From file or swap or for growing stack.
 */
bool try_to_get_page (void *fault_addr);

/* Grow stack. */
bool grow_stack (void *fault_addr);

/* Load page from file. */
bool load_from_file (void *addr, struct sup_page_table_entry *entry);

#endif /* vm/page.h */
