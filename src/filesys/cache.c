#include "cache.h"
#include "filesys.h"
#include "devices/block.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include <string.h>

struct list cache;
struct lock cache_lock;

void
cache_init (void)
{
  list_init (&cache);
  lock_init (&cache_lock);
}

/* Returns a cache entry for the given sector, or creates a new one if none
   exists. If a new entry is created, it is not added to the cache until it is
   filled with data. */
static struct cache_entry *
cache_get_entry (block_sector_t sector)
{
  struct cache_entry *entry;
  lock_acquire (&cache_lock);
  // search for existing cache entry
  struct list_elem *e;
  for (e = list_begin (&cache); e != list_end (&cache); e = list_next (e))
    {
      entry = list_entry (e, struct cache_entry, elem);
      if (entry->sector == sector)
        {
          lock_release (&cache_lock);
          return entry;
        }
    }
  // create new cache entry
  entry = malloc (sizeof *entry);
  entry->sector = sector;
  entry->data = malloc (BLOCK_SECTOR_SIZE);
  entry->dirty = false;
  entry->accessed = false;
  lock_init (&entry->lock);
  lock_release (&cache_lock);
  return entry;
}

/* Removes the least recently accessed cache entry from the cache. */
static void
cache_evict (void)
{
  lock_acquire (&cache_lock);
  struct list_elem *e;
  struct cache_entry *entry;
  while (true)
    {
      e = list_pop_front (&cache);
      entry = list_entry (e, struct cache_entry, elem);
      if (entry->accessed)
        {
          entry->accessed = false;
          list_push_back (&cache, e);
        }
      else
        {
          if (entry->dirty)
            block_write (fs_device, entry->sector, entry->data);
          free (entry->data);
          free (entry);
          lock_release (&cache_lock);
          return;
        }
    }
}

void
cache_read (block_sector_t sector, void *buffer)
{
  struct cache_entry *entry = cache_get_entry (sector);
  lock_acquire (&entry->lock);
  if (entry->data != NULL)
    {
      // entry is in cache, copy data to buffer
      memcpy (buffer, entry->data, BLOCK_SECTOR_SIZE);
      entry->accessed = true;
      lock_release (&entry->lock);
    }
  else
    {
      // entry not in cache, read from disk and add to cache
      block_read (fs_device, sector, entry->data);
      list_push_back (&cache, &entry->elem);
      if (list_size (&cache) > CACHE_SIZE)
        cache_evict ();
      memcpy (buffer, entry->data, BLOCK_SECTOR_SIZE);
      entry->accessed = true;
      lock_release (&entry->lock);
    }
}

void
cache_write (block_sector_t sector, const void *buffer)
{
  struct cache_entry *entry = cache_get_entry (sector);
  lock_acquire (&entry->lock);
  memcpy (entry->data, buffer, BLOCK_SECTOR_SIZE);
  entry->dirty = true;
  entry->accessed = true;
  if (entry->data != NULL)
    {
      // entry already in cache, update accessed timestamp
      list_remove (&entry->elem);
      list_push_back (&cache, &entry->elem);
    }
  else
    {
      // entry not in cache, add to cache
      list_push_back (&cache, &entry->elem);
      if (list_size (&cache) > CACHE_SIZE)
        cache_evict ();
    }
  lock_release (&entry->lock);
}

void
cache_flush (void)
{
  lock_acquire (&cache_lock);
  struct list_elem *e;
  struct cache_entry *entry;
  for (e = list_begin (&cache); e != list_end (&cache); e = list_next (e))
    {
      entry = list_entry (e, struct cache_entry, elem);
      if (entry->dirty)
        block_write (fs_device, entry->sector, entry->data);
    }
  lock_release (&cache_lock);
}
