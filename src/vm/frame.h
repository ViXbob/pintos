#ifndef VM_FRAME_H
#define VM_FRAME_H
#include <list.h>

struct frame_table_entry
{
  void *frame_addr;      /* Virtual address this frame holds. */
  struct thread *owner;  /* Owner of this frame. */
  struct list_elem elem; /* List element in frame table. */
} frame_table_entry;

struct frame_table_entry *new_frame_table_entry (void *frame_addr, struct thread *onwer);



#endif /* vm/frame.h */
