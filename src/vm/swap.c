#include "swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <bitmap.h>
#include <debug.h>

/* Swap table: tracking all free swap slots. */
static struct bitmap *swap_slot_table;

/* Lock for avoid race condition. */
static struct lock swap_slot_table_lock;

/* The swap block provided. */
static struct block *global_swap_block;

#define SECTOR_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

/* Get a new swap slot. */
int get_new_swap_slot (void);

void
swap_init (void)
{
  /* PGSIZE should divide BLOCK_SECTOR_SIZE. */
  ASSERT (SECTOR_PER_PAGE * BLOCK_SECTOR_SIZE == PGSIZE);

  global_swap_block = block_get_role (BLOCK_SWAP);
  if (global_swap_block == NULL)
    {
      PANIC ("Cannot get a valid block device for swap partition.");
    }
  swap_slot_table = bitmap_create (block_size (global_swap_block));
  if (swap_slot_table == NULL)
    {
      PANIC ("Cannot create a bitmap for swap slot table.");
    }
  lock_init (&swap_slot_table_lock);
}

void
swap_destory (void)
{
  bitmap_destroy (swap_slot_table);
}

void
swap_release_slot (int sector_index)
{
  lock_acquire (&swap_slot_table_lock);
  bitmap_set_multiple (swap_slot_table, sector_index, SECTOR_PER_PAGE, false);
  lock_release (&swap_slot_table_lock);
}

void
read_frame_from_block (struct sup_page_table_entry *sup_page_table_entry,
                       void *addr, int sector_index)
{
  ASSERT (sup_page_table_entry != NULL);

  for (int i = 0; i < SECTOR_PER_PAGE; i++)
    {
      block_read (global_swap_block, sector_index + i,
                  addr + i * BLOCK_SECTOR_SIZE);
    }

  /* Release those slots. */
  swap_release_slot (sector_index);

  sup_page_table_entry->swap_index = NOT_IN_SWAP;
}

int
get_new_swap_slot (void)
{

  lock_acquire (&swap_slot_table_lock);
  /* Find consecutive SECTOR_PER_GAGE slots and flip them. */
  size_t sector_index
      = bitmap_scan_and_flip (swap_slot_table, 0, SECTOR_PER_PAGE, false);
  lock_release (&swap_slot_table_lock);

  if (sector_index == BITMAP_ERROR)
    PANIC ("Cannot get enough swap slots.");

  return sector_index;
}

void
write_frame_to_block (struct sup_page_table_entry *sup_page_table_entry,
                      void *addr)
{
  int sector_index = get_new_swap_slot ();

  sup_page_table_entry->swap_index = sector_index;

  for (int i = 0; i < SECTOR_PER_PAGE; i++)
    {
      block_write (global_swap_block, sector_index + i,
                   addr + i * BLOCK_SECTOR_SIZE);
    }
}
