#include "page.h"
#include "devices/timer.h"
#include "filesys/file.h"
#include "frame.h"
#include "swap.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <hash.h>
#include <stdio.h>
#include <string.h>

extern struct lock filesys_lock;
extern bool install_page (void *, void *, bool);
extern bool free_frame_table_entry (struct frame_table_entry *entry,
                                    void *target_addr);

/* Hash function of supplementary page table. */
unsigned sup_page_table_hash_func (const struct hash_elem *e,
                                   void *aux UNUSED);

/* Less function of supplementary page table. */
bool sup_page_table_less_func (const struct hash_elem *a,
                               const struct hash_elem *b, void *aux UNUSED);

/* Destory function for single supplementary page table entry. */
void sup_page_table_entry_free_func (struct hash_elem *e, void *aux UNUSED);

/* Allocate and initialize a supplementary page table entry. */
struct sup_page_table_entry *new_sup_page_table_entry (void *addr,
                                                       uint64_t access_time);

/* Load page from file. */
bool load_from_file (struct sup_page_table_entry *sup_page_table_entry);

/* Load page from swap partition. */
bool load_from_swap (struct sup_page_table_entry *sup_page_table_entry);

unsigned
sup_page_table_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  const struct sup_page_table_entry *entry
      = hash_entry (e, struct sup_page_table_entry, elem);
  /* Fowler–Noll–Vo hash function on address. */
  return hash_bytes (&entry->addr, sizeof (entry->addr));
}

bool
sup_page_table_less_func (const struct hash_elem *a, const struct hash_elem *b,
                          void *aux UNUSED)
{
  const struct sup_page_table_entry *entry_a
      = hash_entry (a, struct sup_page_table_entry, elem);
  const struct sup_page_table_entry *entry_b
      = hash_entry (b, struct sup_page_table_entry, elem);
  /* Virtual address in supplementary page table must be unique. */
  return (uint32_t)entry_a->addr < (uint32_t)entry_b->addr;
}

void
sup_page_table_init (sup_page_table *sup_page_table)
{
  hash_init (sup_page_table, sup_page_table_hash_func,
             sup_page_table_less_func, NULL);
}

void
sup_page_table_entry_free_func (struct hash_elem *e, void *aux UNUSED)
{
  struct sup_page_table_entry *sup_page_table_entry
      = hash_entry (e, struct sup_page_table_entry, elem);
  lock_acquire (&sup_page_table_entry->lock);
  ASSERT (!sup_page_table_entry->is_mmap);
  switch (sup_page_table_entry->status)
    {
    case IN_MEMORY:
      {
        ASSERT (sup_page_table_entry->frame_table_entry != NULL);
        free_frame_table_entry (
            sup_page_table_entry->frame_table_entry,
            sup_page_table_entry->frame_table_entry->frame_addr);
        pagedir_clear_page (thread_current ()->pagedir,
                            sup_page_table_entry->addr);
        break;
      }
    case IN_SWAP:
      {
        swap_release_slot (sup_page_table_entry->swap_index);
        break;
      }
    case IN_FILESYS:
        break;
    case INVALID:
        PANIC ("Sup page table entry should not be invalid.");
    default:
        NOT_REACHED ();
    }
  lock_release (&sup_page_table_entry->lock);
  free (sup_page_table_entry);
}

void
sup_page_table_free (sup_page_table *sup_page_table)
{
  hash_destroy (sup_page_table, sup_page_table_entry_free_func);
}

struct sup_page_table_entry *
new_sup_page_table_entry (void *addr, uint64_t access_time)
{
  ASSERT (is_user_vaddr (addr));
  /* Allocate memory for new supplementary page table entry. You must free it
   * properly. */
  struct sup_page_table_entry *entry = (struct sup_page_table_entry *)malloc (
      sizeof (struct sup_page_table_entry));

  /* Mlloc failed. */
  if (entry == NULL)
    return NULL;

  /* Virtual address must be page-aligned. */
  entry->addr = pg_round_down (addr);
  entry->status = INVALID;
  entry->frame_table_entry = NULL;
  entry->access_time = access_time;
  entry->writable = true;
  entry->dirty = false;
  entry->ref_bit = 1;
  entry->swap_index = NOT_IN_SWAP;
  entry->file = NULL;
  entry->offset = 0;
  entry->read_bytes = 0;
  entry->zero_bytes = 0;
  entry->is_mmap = false;
  lock_init (&entry->lock);
  // printf ("address of sup_page_table_entry_lock is %p.\n", &entry->lock);
  return entry;
}

struct sup_page_table_entry *
sup_page_table_find_entry (sup_page_table *table, void *target_addr)
{
  /* table or target address is empty. */
  if (table == NULL || target_addr == NULL)
    return NULL;

  struct sup_page_table_entry entry;
  /* Round down address to make sure it is page-aligned. */
  entry.addr = pg_round_down (target_addr);

  struct hash_elem *e = hash_find (table, &entry.elem);

  if (e == NULL)
    return NULL;

  return hash_entry (e, struct sup_page_table_entry, elem);
}

bool
try_to_get_page (void *fault_addr, void *esp)
{
  ASSERT (is_user_vaddr (fault_addr));

  /* Null address. */
  if (fault_addr == NULL)
    return false;

  struct thread *t = thread_current ();
  struct sup_page_table_entry *sup_page_table_entry
      = sup_page_table_find_entry (&t->sup_page_table, fault_addr);

  /* Page is not found, grow stack. */
  if (sup_page_table_entry == NULL)
    {
      /* This address does not appear to be a stack access. */
      if (fault_addr < esp - 32)
        return false;

      return grow_stack (fault_addr);
    }
  else
    {
      switch (sup_page_table_entry->status)
        {
        case IN_MEMORY:
          PANIC ("Impossible");
        case IN_SWAP:
          return load_from_swap (sup_page_table_entry);
        case IN_FILESYS:
          return load_from_file (sup_page_table_entry);
        case INVALID:
          PANIC ("Sup page table entry should not be invalid.");
        default:
          NOT_REACHED ();
        }
    }
}

bool
grow_stack (void *fault_addr)
{
  struct thread *t = thread_current ();

  /* Allocate new supplementary page table entry. */
  struct sup_page_table_entry *sup_page_table_entry
      = new_sup_page_table_entry (fault_addr, timer_ticks ());

  /* Fail to allocate new supplementary page table entry. */
  if (sup_page_table_entry == NULL)
    return false;

  struct frame_table_entry *frame_table_entry
      = frame_get_page (sup_page_table_entry);

  /* Fail to get new frame table entry. */
  if (frame_table_entry == NULL)
    {
      free (sup_page_table_entry);
      return false;
    }

  lock_acquire (&frame_table_entry->lock);
  void *kpage = frame_table_entry->frame_addr;
  void *upage = sup_page_table_entry->addr;

  if (!install_page (upage, kpage, true))
    {
      free (sup_page_table_entry);
      free_frame_table_entry (frame_table_entry, kpage);
      return false;
    }

  /* Free resources you allocated. */
  if (hash_insert (&t->sup_page_table, &sup_page_table_entry->elem) != NULL)
    {
      free (sup_page_table_entry);
      free_frame_table_entry (frame_table_entry, kpage);
      /* Must clear the page you installed. */
      pagedir_clear_page (t->pagedir, upage);
      return false;
    }

  sup_page_table_entry->status = IN_MEMORY;
  sup_page_table_entry->frame_table_entry = frame_table_entry;
  lock_release (&frame_table_entry->lock);
  return true;
}

bool
load_from_file (struct sup_page_table_entry *sup_page_table_entry)
{
  struct frame_table_entry *frame_table_entry
      = frame_get_page (sup_page_table_entry);

  /* Fail to get new frame table entry. */
  if (frame_table_entry == NULL)
    return false;

  lock_acquire (&frame_table_entry->lock);
  lock_acquire (&sup_page_table_entry->lock);

  /* Variables used for file load. */
  void *kpage = frame_table_entry->frame_addr;
  void *upage = sup_page_table_entry->addr;
  struct file *file = sup_page_table_entry->file;
  int32_t offset = sup_page_table_entry->offset;
  size_t page_read_bytes = sup_page_table_entry->read_bytes;
  size_t page_zero_bytes = sup_page_table_entry->zero_bytes;
  bool writable = sup_page_table_entry->writable;

  lock_acquire (&filesys_lock);

  /* File read failed. */
  if (file_read_at (file, kpage, page_read_bytes, offset) != (int)page_read_bytes)
    {
      free_frame_table_entry (frame_table_entry, kpage);
      lock_release (&filesys_lock);
      lock_release (&sup_page_table_entry->lock);
      return false;
    }

  lock_release (&filesys_lock);

  /* Set the zero bytes. */
  memset (kpage + page_read_bytes, 0, page_zero_bytes);

  if (!install_page (upage, kpage, writable))
    {
      free_frame_table_entry (frame_table_entry, kpage);
      lock_release (&sup_page_table_entry->lock);
      return false;
    }

  sup_page_table_entry->status = IN_MEMORY;
  sup_page_table_entry->frame_table_entry = frame_table_entry;

  lock_release (&sup_page_table_entry->lock);
  lock_release (&frame_table_entry->lock);
  return true;
}

bool
load_from_swap (struct sup_page_table_entry *sup_page_table_entry)
{
  ASSERT (sup_page_table_entry->swap_index != NOT_IN_SWAP);

  struct frame_table_entry *frame_table_entry
      = frame_get_page (sup_page_table_entry);

  /* Fail to get new frame table entry. */
  if (frame_table_entry == NULL)
    return false;

  lock_acquire (&frame_table_entry->lock);
  lock_acquire (&sup_page_table_entry->lock);

  void *upage = sup_page_table_entry->addr;
  void *kpage = frame_table_entry->frame_addr;
  bool writable = sup_page_table_entry->writable;
  bool success = install_page (upage, kpage, writable);

  if (!success)
    {
      free_frame_table_entry (frame_table_entry, kpage);
      lock_release (&sup_page_table_entry->lock);
      return false;
    }

  sup_page_table_entry->access_time = timer_ticks ();
  sup_page_table_entry->ref_bit = 1;

  read_frame_from_block (sup_page_table_entry, frame_table_entry->frame_addr,
                         sup_page_table_entry->swap_index);
  sup_page_table_entry->status = IN_MEMORY;
  sup_page_table_entry->swap_index = NOT_IN_SWAP;

  sup_page_table_entry->frame_table_entry = frame_table_entry;
  lock_release (&sup_page_table_entry->lock);
  lock_release (&frame_table_entry->lock);
  return true;
}

bool
lazy_load_segment (struct file *file, int32_t ofs, uint8_t *upage,
                   uint32_t read_bytes, uint32_t zero_bytes, bool writable,
                   bool is_mmap)
{
  ASSERT (is_user_vaddr (upage));

  int32_t offset = ofs;
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Create new supplementary page table entry. */
      struct sup_page_table_entry *sup_page_table_entry
          = new_sup_page_table_entry (upage, timer_ticks ());

      if (sup_page_table_entry == NULL)
        return false;

      sup_page_table_entry->status = IN_FILESYS;

      /* Used for file load. */
      sup_page_table_entry->file = file;
      sup_page_table_entry->offset = offset;
      sup_page_table_entry->read_bytes = page_read_bytes;
      sup_page_table_entry->zero_bytes = page_zero_bytes;
      sup_page_table_entry->writable = writable;

      /* Used for mmap. */
      sup_page_table_entry->is_mmap = is_mmap;

      /* Fail to insert into hash table. There has already been a supplementary
       * page table entry with same user address. This means that the return
       * value of hash_insert is non-empty. */
      if (hash_insert (&thread_current ()->sup_page_table,
                       &sup_page_table_entry->elem)
          != NULL)
        {
          free (sup_page_table_entry);
          return false;
        }

      /* Advance. */
      offset += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }

  return true;
}