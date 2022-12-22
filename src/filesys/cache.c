#include "cache.h"
#include "devices/block.h"
#include "devices/timer.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <string.h>

struct cache_entry caches[CACHE_SIZE];
struct lock cache_lock;
extern struct block *fs_device;

static void
cache_entry_flush (struct cache_entry *entry)
{
  if (entry->accessed && entry->dirty)
    {
      block_write (fs_device, entry->sector, entry->data);
      entry->dirty = false;
    }
}

static void
cache_entry_init (struct cache_entry *entry, block_sector_t sector)
{
  entry->accessed = true;
  entry->dirty = false;
  entry->time = timer_ticks ();
  lock_init (&entry->lock);
  entry->sector = sector;
  block_read (fs_device, sector, entry->data);
}

/* Removes the least recently accessed cache entry from the cache. */
static struct cache_entry *
cache_evict (void)
{
  lock_acquire (&cache_lock);
  struct cache_entry *entry;
  for (int i = 0; i < CACHE_SIZE; i++)
    {
      if (lock_held_by_current_thread (&caches[i].lock)
          || !lock_try_acquire (&caches[i].lock))
        continue;
      if (entry == NULL || entry->time > caches[i].time)
        {
          if (entry != NULL)
            lock_release (&entry->lock);
          entry = &caches[i];
        }
    }

  /* Write-behind: write back to disk when a dirty block is evicted. */
  cache_entry_flush (entry);

  lock_release (&entry->lock);
  lock_release (&cache_lock);
  return entry;
}

/* Returns a cache entry for the given sector, or creates a new one if none
   exists. If a new entry is created, it is not added to the cache until it is
   filled with data. */
static struct cache_entry *
cache_get_entry (block_sector_t sector)
{
  struct cache_entry *entry = NULL, *unused_entry = NULL;
  lock_acquire (&cache_lock);
  for (int i = 0; i < CACHE_SIZE; i++)
    {
      if (unused_entry == NULL && !caches->accessed)
        unused_entry = &caches[i];

      if (caches[i].sector == sector)
        {
          entry = &caches[i];
          break;
        }
    }

  /* Hit. */
  if (entry != NULL)
    {
      /* Update last access time. */
      entry->time = timer_ticks ();
      lock_release (&cache_lock);
      return entry;
    }

  /* Miss and evict one entry. */
  if (unused_entry == NULL)
    unused_entry = cache_evict ();

  cache_entry_init (unused_entry, sector);
  lock_release (&cache_lock);
  return unused_entry;
}

void
cache_init (void)
{
  lock_init (&cache_lock);
  memset (caches, 0, sizeof (caches));
}

void
cache_read (block_sector_t sector, void *buffer)
{
  /* TODO: read-ahead has not been implemented. */
  struct cache_entry *entry = cache_get_entry (sector);
  lock_acquire (&entry->lock);
  memcpy (buffer, entry->data, BLOCK_SECTOR_SIZE);
  lock_release (&entry->lock);
}

void
cache_write (block_sector_t sector, const void *buffer)
{
  struct cache_entry *entry = cache_get_entry (sector);
  lock_acquire (&entry->lock);
  entry->dirty = true;
  memcpy (entry->data, buffer, BLOCK_SECTOR_SIZE);
  lock_release (&entry->lock);
}

void
cache_flush (void)
{
  lock_acquire (&cache_lock);
  for (int i = 0; i < CACHE_SIZE; i++)
    cache_entry_flush (&caches[i]);
  lock_release (&cache_lock);
}
