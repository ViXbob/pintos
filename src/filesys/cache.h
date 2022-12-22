#ifndef CACHE_H
#define CACHE_H

#include "devices/block.h"
#include <stdbool.h>
#include "threads/synch.h"

#define CACHE_SIZE 64

struct cache_entry {
  block_sector_t sector;
  void *data;
  bool dirty;
  bool accessed;
  struct lock lock;
  struct list_elem elem;
};

void cache_init (void);
void cache_read (block_sector_t, void *);
void cache_write (block_sector_t, const void *);
void cache_flush (void);

#endif
