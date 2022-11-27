#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "page.h"
#include <list.h>

struct frame_table_entry
{
  void *frame_addr;     /* Virtual address this frame holds. */
  struct thread *owner; /* Owner of this frame. */
  struct sup_page_table_entry *
      sup_page_table_entry; /* Corresponding supplementary page table entry. */
  struct list_elem elem;    /* List element in frame table. */
} frame_table_entry;

/* Initialize frame table. */
void frame_table_init (void);

/* Allocate and initialize a frame table entry. */
struct frame_table_entry *
new_frame_table_entry (void *frame_addr, struct thread *onwer,
                       struct sup_page_table_entry *sup_page_table_entry);

/* Get a new frame page. */
struct frame_table_entry *
frame_get_page (struct sup_page_table_entry *sup_page_table_entry);

/* Action function for foreach function. The return value will control the loop. */
typedef bool frame_table_entry_action_func(struct frame_table_entry*, void *);

/* For each element in frame table, and do some actions. */
void frame_table_foreach (frame_table_entry_action_func *action_func, void *aux);

/* Free a frame page with virtual address. */
void frame_free_page (void *frame_addr);
#endif /* vm/frame.h */
