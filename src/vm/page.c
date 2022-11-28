#include "page.h"
#include "devices/timer.h"
#include "filesys/file.h"
#include "frame.h"
#include "swap.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <hash.h>

extern struct lock filesys_lock;
extern bool install_page (void *, void *, bool);

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
  hash_init (&sup_page_table, sup_page_table_hash_func,
             sup_page_table_less_func, NULL);
}

struct sup_page_table_entry *
new_sup_page_table_entry (void *addr, uint64_t access_time)
{
  /* Allocate memory for new supplementary page table entry. You must free it
   * properly. */
  struct sup_page_table_entry *entry
      = malloc (sizeof (struct sup_page_table_entry));

  /* Mlloc failed. */
  if (entry == NULL)
    return NULL;

  /* Virtual address must be page-aligned. */
  entry->addr = pg_round_down (addr);
  entry->access_time = access_time;
  entry->swap_index = NOT_IN_SWAP;
  entry->from_file = false;
  entry->file = NULL;
  entry->offset = 0;
  entry->read_bytes = 0;
  entry->zero_bytes = 0;
  entry->writable = false;
  entry->is_mmap = false;
  lock_init (&entry->lock);
  return entry;
}

struct sup_page_table_entry *
find_entry (sup_page_table *table, void *target_addr)
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
try_to_get_page (void *fault_addr)
{
  /* Null address. */
  if (fault_addr == NULL)
    return false;

  struct thread *t = thread_current ();
  struct sup_page_table_entry *entry
      = find_entry (&t->sup_page_table, fault_addr);

  /* Page is not found, grow stack. */
  if (entry == NULL)
    {
      return grwo_stack (fault_addr);
    }
  else if (entry->from_file)
    {
      return load_from_file (fault_addr, entry);
    }
  else if (entry->swap_index != NOT_IN_SWAP)
    {
      /* Have not implemented swap yet.*/
      NOT_REACHED ();
    }
  else
    {
      /* Impossible. */
      NOT_REACHED ();
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

  void *kpage = frame_table_entry->frame_addr;
  void *upage = sup_page_table_entry->addr;

  bool success
      = install_page (upage, kpage, true)
        && (hash_insert (&t->sup_page_table, &sup_page_table_entry->elem)
            == NULL);

  /* Free resources you allocated. */
  if (!success)
    {
      free (sup_page_table_entry);
      frame_free_page (kpage);
      /* Must clear the page you may installed. */
      pagedir_clear_page (t->pagedir, upage);
      /* Remove the element you insert into supplementary page table. */
      hash_delete (&t->sup_page_table, &sup_page_table_entry->elem);

      return false;
    }

  return true;
}

bool
load_from_file (void *addr, struct sup_page_table_entry *sup_page_table_entry)
{
  struct frame_table_entry *frame_table_entry
      = frame_get_page (sup_page_table_entry);

  /* Fail to get new frame table entry. */
  if (frame_table_entry == NULL)
    return false;

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
  file_seek (file, offset);

  /* File read failed. */
  if (file_read (file, kpage, page_read_bytes) != (int)page_read_bytes)
    {
      frame_free_page (kpage);
      lock_release (&filesys_lock);
      lock_release (&sup_page_table_entry->lock);
      return false;
    }

  lock_release (&filesys_lock);

  /* Set the zero bytes. */
  memset (kpage + page_read_bytes, 0, page_zero_bytes);

  if (!install_page (upage, kpage, writable))
    {
      frame_free_page (kpage);
      lock_release (&sup_page_table_entry->lock);
      return false;
    }

  lock_release (&sup_page_table_entry->lock);
  return true;
}