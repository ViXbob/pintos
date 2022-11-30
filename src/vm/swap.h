#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "frame.h"
#include <stdbool.h>

#define NOT_IN_SWAP (-1)

/* Initialize the swap partition. */
void swap_init (void);

/* Deallocate all resources of swap partition. */
void swap_destory (void);

/* Release corresponding slot (one page) in swap by given sector index. */
void swap_release_slot (int sector_index);

/* Read a frame frow disk and then realse it. */
void read_frame_from_block (struct frame_table_entry *frame, int sector_index);

/* Get a new swap slot. */
int get_new_swap_slot (void);

/* Write a frame frow disk. */
void write_frame_to_block (struct frame_table_entry *frame);

#endif /* vm/swap.h */
