#ifndef CACHE_H
#define CACHE_H

#include "devices/block.h"
#include "threads/synch.h"
#include <stdbool.h>
#include <stdint.h>

#define CACHE_SIZE 64

struct cache_entry
{
  bool accessed;                   /* Whether this entry is accessed or not. */
  bool dirty;                      /* Whether this entry is dirty or not. */
  int64_t time;                    /* Last access time. */
  struct lock lock;                /*Cache entry lock. */
  block_sector_t sector;           /* Corresponding block sector number. */
  uint8_t data[BLOCK_SECTOR_SIZE]; /* Corresponding block data. */
};

void cache_init (void);
void cache_read (block_sector_t, void *);
void cache_write (block_sector_t, const void *);
void cache_flush (void);

#endif
