#include "cache.h"
#include "devices/block.h"
#include "devices/timer.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <string.h>

struct cache_entry caches[CACHE_SIZE];
struct lock cache_lock;
extern struct block *fs_device;

void cache_entry_flush (struct cache_entry *entry);
void cache_entry_init (struct cache_entry *entry, block_sector_t sector);
struct cache_entry *cache_evict (void);
struct cache_entry *cache_get_entry (block_sector_t sector);

void
cache_entry_flush (struct cache_entry *entry)
{
  if (entry->accessed && entry->dirty)
    {
      block_write (fs_device, entry->sector, entry->data);
      entry->dirty = false;
    }
}

void
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
struct cache_entry *
cache_evict (void)
{
  struct cache_entry *entry = NULL;
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
      else
        /* You must release caches[i].lock which is acquired above. */
        lock_release (&caches[i].lock);
    }

  /* Write-behind: write back to disk when a dirty block is evicted. */
  cache_entry_flush (entry);

  lock_release (&entry->lock);
  return entry;
}

/* Returns a cache entry for the given sector, or creates a new one if none
   exists. If a new entry is created, it is not added to the cache until it is
   filled with data. */
struct cache_entry *
cache_get_entry (block_sector_t sector)
{
  struct cache_entry *entry = NULL, *unused_entry = NULL;
  lock_acquire (&cache_lock);
  for (int i = 0; i < CACHE_SIZE; i++)
    {
      if (unused_entry == NULL && !caches[i].accessed)
        unused_entry = &caches[i];

      if (caches[i].accessed && caches[i].sector == sector)
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
  for (int i = 0; i < CACHE_SIZE; i++)
    {
      caches[i].accessed = false;
      caches[i].dirty = false;
      caches[i].time = 0;
      lock_init (&caches[i].lock);
      caches[i].sector = 0;
      memset (caches[i].data, 0, BLOCK_SECTOR_SIZE);
    }
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

/* Wrap block_read. */
void
read_wrapper (struct block *block, block_sector_t sector, void *buffer)
{
#if ENABLE_CACHE
  if (block == fs_device)
    cache_read (sector, buffer);
  else
    block_read (block, sector, buffer);
#else
  block_read (block, sector, buffer);
#endif
}

/* Wrap block_write. */
void
write_wrapper (struct block *block, block_sector_t sector, const void *buffer)
{
#if ENABLE_CACHE
  if (block == fs_device)
    cache_write (sector, buffer);
  else
    block_write (block, sector, buffer);
#else
  block_write (block, sector, buffer);
#endif
}