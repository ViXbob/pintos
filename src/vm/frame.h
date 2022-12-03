#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "page.h"
#include "threads/synch.h"
#include <list.h>

struct frame_table_entry
{
  void *frame_addr;     /* Virtual address this frame holds. */
  struct thread *owner; /* Owner of this frame. */
  struct sup_page_table_entry *
      sup_page_table_entry; /* Corresponding supplementary page table entry. */
  struct list_elem elem;    /* List element in frame table. */
  struct lock lock;         /* Frame table entry lock. */
};

/* Initialize frame table. */
void frame_table_init (void);

/* Get a new frame page. */
struct frame_table_entry *
frame_get_page (struct sup_page_table_entry *sup_page_table_entry);

/* Free a frame page with virtual address. */
void frame_free_page (void *frame_addr);
#endif /* vm/frame.h */
