#include "frame.h"
#include "devices/timer.h"
#include "swap.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include <hash.h>
#include <list.h>
#include <stdio.h>

extern struct lock filesys_lock;

/* Frame table lock, you should lock when using frame list. */
struct lock frame_table_lock;

/* Frame list which stores all frame table entries. */
struct list frame_table_list;

/* Allocate and initialize a frame table entry. */
struct frame_table_entry *
new_frame_table_entry (void *frame_addr, struct thread *onwer,
                       struct sup_page_table_entry *sup_page_table_entry);

/* Action function for foreach function. The return value will control the
 * loop. */
typedef bool frame_table_entry_action_func (struct frame_table_entry *,
                                            void *);

/* For each element in frame table, and do some actions. */
void frame_table_foreach (frame_table_entry_action_func *action_func,
                          void *aux);

/* Foreach action function: Free frame table entry function. */
bool free_frame_table_entry (struct frame_table_entry *entry,
                             void *target_addr);

enum
{
  LRU,
  CLOCK
};

#define EVICT_METHOD LRU

static struct list_elem *clock_hand;

struct frame_table_entry *find_one_to_evict (void);

struct frame_table_entry *evict_one_frame (void);

void
frame_table_init (void)
{
  list_init (&frame_table_list);
  lock_init (&frame_table_lock);
  clock_hand = list_head (&frame_table_list);
}

struct frame_table_entry *
new_frame_table_entry (void *frame_addr, struct thread *onwer,
                       struct sup_page_table_entry *sup_page_table_entry)
{
  /* Allocate memory. You must free the memory you allocate. */
  struct frame_table_entry *frame_table_entry
      = malloc (sizeof (struct frame_table_entry));

  /* malloc failed. */
  if (frame_table_entry == NULL)
    return NULL;

  /* Initialize. */
  frame_table_entry->frame_addr = frame_addr;
  frame_table_entry->owner = onwer;
  frame_table_entry->sup_page_table_entry = sup_page_table_entry;
  lock_init (&frame_table_entry->lock);

  return frame_table_entry;
}

struct frame_table_entry *
find_one_to_evict (void)
{
  switch (EVICT_METHOD)
    {
    case LRU:
      {
        struct list_elem *e;
        struct frame_table_entry *min_frame_table_entry = NULL;

        for (e = list_begin (&frame_table_list);
             e != list_end (&frame_table_list); e = list_next (e))
          {
            struct frame_table_entry *frame_table_entry
                = list_entry (e, struct frame_table_entry, elem);
            if (!lock_held_by_current_thread (&frame_table_entry->lock)
                && !lock_try_acquire (&frame_table_entry->lock))
                  continue;
            if (min_frame_table_entry == NULL
                || frame_table_entry->sup_page_table_entry->access_time
                        < min_frame_table_entry->sup_page_table_entry
                              ->access_time)
              {
                if (min_frame_table_entry != NULL)
                  lock_release (&min_frame_table_entry->lock);
                min_frame_table_entry = frame_table_entry;
              }
            else
              lock_release (&frame_table_entry->lock);
          }
        lock_release (&min_frame_table_entry->lock);
        return min_frame_table_entry;
      }
    case CLOCK:
      {
        if (list_empty (&frame_table_list))
          return NULL;
        clock_hand = list_head (&frame_table_list);
        struct frame_table_entry *frame_table_entry = NULL;
        while (frame_table_entry == NULL)
          {
            clock_hand = (clock_hand == list_rbegin (&frame_table_list)
                              ? list_begin (&frame_table_list)
                              : list_next (clock_hand));
            frame_table_entry
                = list_entry (clock_hand, struct frame_table_entry, elem);
            if (!lock_held_by_current_thread (&frame_table_entry->lock)
                && !lock_try_acquire (&frame_table_entry->lock))
              continue;
            if (frame_table_entry->sup_page_table_entry->ref_bit)
              {
                frame_table_entry->sup_page_table_entry->ref_bit = 0;
                lock_release (&frame_table_entry->lock);
                frame_table_entry = NULL;
              }
          }
        lock_release (&frame_table_entry->lock);
        return frame_table_entry;
      }
    default:
      {
        PANIC ("EVICT METHOD SHOULD EITHER BE LRU OR CLOCK.");
      }
    }
}

struct frame_table_entry *
evict_one_frame (void)
{
  struct frame_table_entry *frame_table_entry = find_one_to_evict ();
  struct sup_page_table_entry *sup_page_table_entry
      = frame_table_entry->sup_page_table_entry;
  lock_acquire (&frame_table_entry->lock);
  lock_acquire (&sup_page_table_entry->lock);
  sup_page_table_entry->dirty |= pagedir_is_dirty (
      frame_table_entry->owner->pagedir, sup_page_table_entry->addr);
  ASSERT (sup_page_table_entry->status == IN_MEMORY);
  if (sup_page_table_entry->is_mmap && sup_page_table_entry->dirty)
    {
      lock_acquire (&filesys_lock);
      file_write_at (sup_page_table_entry->file, sup_page_table_entry->addr,
                     sup_page_table_entry->read_bytes,
                     sup_page_table_entry->offset);
      lock_release (&filesys_lock);
      sup_page_table_entry->status = IN_FILESYS;
      sup_page_table_entry->dirty = false;
    }
  else
    {
      sup_page_table_entry->status = IN_SWAP;
      write_frame_to_block (sup_page_table_entry,
                            frame_table_entry->frame_addr);
    }
  sup_page_table_entry->frame_table_entry = NULL;
  pagedir_clear_page (frame_table_entry->owner->pagedir,
                      sup_page_table_entry->addr);
  ASSERT (sup_page_table_entry->status == IN_FILESYS
          || sup_page_table_entry->status == IN_SWAP);
  lock_release (&sup_page_table_entry->lock);
  lock_release (&frame_table_entry->lock);
  return frame_table_entry;
}

struct frame_table_entry *
frame_get_page (struct sup_page_table_entry *sup_page_table_entry)
{
  /* Supplementary page table entry must be non-null. */
  if (sup_page_table_entry == NULL)
    return NULL;

  /* Allocate a new page from memory. You should free it properly. */
  void *kernel_page = palloc_get_page (PAL_USER | PAL_ZERO);
  struct frame_table_entry *frame_table_entry;
  if (kernel_page == NULL)
    {
      // printf ("We want to evict one page!\n");
      lock_acquire (&sup_page_table_entry->lock);
      /* Evict one frame from frame table by LRU method. */
      frame_table_entry = evict_one_frame ();

      frame_table_entry->owner = thread_current ();
      frame_table_entry->sup_page_table_entry = sup_page_table_entry;
      lock_release (&sup_page_table_entry->lock);

      return frame_table_entry;
    }

  /* Create a new frame table entry. */
  frame_table_entry = new_frame_table_entry (kernel_page, thread_current (),
                                             sup_page_table_entry);

  /* Fail to create new frame table entry. */
  if (frame_table_entry == NULL)
    {
      /* Free unused page. */
      palloc_free_page (kernel_page);
      return NULL;
    }

  /* Acquire lock when using modifying frame table list. */
  lock_acquire (&frame_table_lock);
  list_push_back (&frame_table_list, &frame_table_entry->elem);
  lock_release (&frame_table_lock);

  return frame_table_entry;
}

void
frame_table_foreach (frame_table_entry_action_func *action_func, void *aux)
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
free_frame_table_entry (struct frame_table_entry *frame_table_entry,
                        void *target_addr)
{
  if (frame_table_entry->frame_addr == target_addr)
    {
      /* Remove this entry from frame table list. */
      lock_acquire (&frame_table_lock);
      list_remove (&frame_table_entry->elem);
      lock_release (&frame_table_lock);
      /* Free the page this entry holds. */
      palloc_free_page (frame_table_entry->frame_addr);
      /* Free the memory this entry occupies. */
      free (frame_table_entry);
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