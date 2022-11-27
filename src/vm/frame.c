#include "frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include <list.h>

/* Frame table lock, you should lock when using frame list. */
struct lock frame_table_lock;

/* Frame list which stores all frame table entries. */
struct list frame_table_list;

/* Foreach action function: Free frame table entry function. */
bool free_frame_table_entry (struct frame_table_entry *entry,
                             void *target_addr);

void
frame_table_init (void)
{
  list_init (&frame_table_list);
  lock_init (&frame_table_lock);
}

struct frame_table_entry *
new_frame_table_entry (void *frame_addr, struct thread *onwer,
                       struct sup_page_table_entry *sup_page_table_entry)
{
  /* Allocate memory. You must free the memory you allocate. */
  struct frame_table_entry *entry = malloc (sizeof (struct frame_table_entry));

  /* malloc failed. */
  if (entry == NULL)
    return NULL;

  /* Initialize. */
  entry->frame_addr = frame_addr;
  entry->owner = onwer;
  entry->sup_page_table_entry = sup_page_table_entry;

  return entry;
}

/* Get a new frame page. */
struct frame_table_entry *
frame_get_page (struct sup_page_table_entry *sup_page_table_entry)
{
  /* Supplementary page table entry must be non-null. */
  if (sup_page_table_entry == NULL)
    return NULL;

  /* Allocate a new page from memory. You should free it properly. */
  void *kernel_page = palloc_get_page (PAL_USER | PAL_ZERO);
  struct frame_table_entry *frame_entry;
  if (kernel_page == NULL)
    {
      /* You should evict a page from frame table. */
      return NULL;
    }

  /* Create a new frame table entry. */
  frame_entry = new_frame_table_entry (kernel_page, thread_current (),
                                       sup_page_table_entry);

  /* Fail to create new frame table entry. */
  if (frame_entry == NULL)
    {
      /* Free unused page. */
      palloc_free_page (kernel_page);
      return NULL;
    }

  /* Acquire lock when using modifying frame table list. */
  lock_acquire (&frame_table_lock);
  list_push_back (&frame_table_list, &frame_entry->elem);
  lock_release (&frame_table_lock);

  return frame_entry;
}

void
frame_table_foreach_if (frame_table_entry_action_func *action_func, void *aux)
{
  struct list_elem *e;

  for (e = list_begin (&frame_table_list); e != list_end (&frame_table_list);
       e = list_next (e))
    {
      struct frame_table_entry *entry
          = list_entry (e, struct frame_table_entry, elem);
      if (action_func (entry, aux))
        return;
    }
}

bool
free_frame_table_entry (struct frame_table_entry *entry, void *target_addr)
{
  if (entry->frame_addr == target_addr)
    {
      /* Remove this entry from frame table list. */
      lock_acquire (&frame_table_lock);
      list_remove (&entry->elem);
      lock_release (&frame_table_lock);
      /* Free the page this entry holds. */
      palloc_free_page (entry->frame_addr);
      /* Free the memory this entry occupies. */
      free (entry);
      return true;
    }
  return false;
}

void
frame_free_page (void *frame_addr)
{
  /* frame address must be non-empty. */
  if (frame_addr == NULL)
    return;
  frame_table_foreach (free_frame_table_entry, frame_addr);
}