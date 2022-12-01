#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "frame.h"
#include "page.h"
#include <stdbool.h>

#define NOT_IN_SWAP (-1)

/* Initialize the swap partition. */
void swap_init (void);

/* Deallocate all resources of swap partition. */
void swap_destory (void);

/* Read a frame frow disk and then realse it. */
void read_frame_from_block (struct sup_page_table_entry *sup_page_table_entry, void *addr, int sector_index);

/* Write a frame frow disk. */
void write_frame_to_block (struct sup_page_table_entry *sup_page_table_entry, void *addr);

#endif /* vm/swap.h */
