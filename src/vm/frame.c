#include "frame.h"
#include "devices/timer.h"
#include "swap.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <list.h>
#include <stdio.h>
#include <hash.h>

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

bool frame_access_time_less (const struct list_elem *a,
                             const struct list_elem *b, void *aux UNUSED);

enum
{
  LRU,
  CLOCK
};

#define EVICT_METHOD CLOCK

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

bool
frame_access_time_less (const struct list_elem *a, const struct list_elem *b,
                        void *aux UNUSED)
{
  struct frame_table_entry *frame_a
      = list_entry (a, struct frame_table_entry, elem);
  struct frame_table_entry *frame_b
      = list_entry (b, struct frame_table_entry, elem);
  struct sup_page_table_entry *page_a = frame_a->sup_page_table_entry;
  struct sup_page_table_entry *page_b = frame_b->sup_page_table_entry;
  bool less_than = page_a->access_time < page_b->access_time;
  if (page_a->writable != page_b->writable)
    {
      return page_a->writable;
    }
  return less_than;
}

struct frame_table_entry *
find_one_to_evict (void)
{
  switch (EVICT_METHOD)
    {
    case LRU:
      {
        struct list_elem *min_elem
            = list_min (&frame_table_list, frame_access_time_less, NULL);
        struct frame_table_entry *frame_table_entry
            = list_entry (min_elem, struct frame_table_entry, elem);
        return frame_table_entry;
      }
    case CLOCK:
      {
        if (list_empty (&frame_table_list))
          return NULL;
        struct frame_table_entry *frame_table_entry = NULL;
        while (frame_table_entry == NULL)
          {
            clock_hand = (clock_hand == list_rbegin (&frame_table_list)
                              ? list_begin (&frame_table_list)
                              : list_next (clock_hand));
            frame_table_entry
                = list_entry (clock_hand, struct frame_table_entry, elem);
            if (frame_table_entry->sup_page_table_entry->ref_bit)
              {
                frame_table_entry->sup_page_table_entry->ref_bit = 0;
                frame_table_entry = NULL;
              }
            else if (clock_hand == list_begin (&frame_table_list))
              {
                frame_table_entry = NULL;
              }
          }
        // printf ("writable is %d\n", frame_table_entry->sup_page_table_entry->writable);
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
  // printf ("start evict.\n");
  struct frame_table_entry *frame_table_entry = find_one_to_evict ();
  lock_acquire (&frame_table_lock);
  frame_table_entry->sup_page_table_entry->dirty
      |= pagedir_is_dirty (frame_table_entry->owner->pagedir,
                           frame_table_entry->sup_page_table_entry->addr);
  write_frame_to_block (frame_table_entry->sup_page_table_entry,
                        frame_table_entry->frame_addr);
  pagedir_clear_page (frame_table_entry->owner->pagedir,
                      frame_table_entry->sup_page_table_entry->addr);
  lock_release (&frame_table_lock);
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