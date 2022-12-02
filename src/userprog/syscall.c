#include "userprog/syscall.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>

#ifdef VM
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
extern bool free_frame_table_entry (struct frame_table_entry *entry,
                                    void *target_addr);
#endif

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t)-1)

/* Maximum characters in a filename written by readdir(). */
#define READDIR_MAX_LEN 14

/* Typical return values from main() and arguments to exit(). */
#define EXIT_SUCCESS 0 /* Successful execution. */
#define EXIT_FAILURE 1 /* Unsuccessful execution. */

/* Standard input/output fd */
#define STDIN 0
#define STDOUT 1

/* Number of system call. */
#define SYSCALL_NUM 20

/* System call handler function type. */
typedef void syscall_handler_func (struct intr_frame *f);

static syscall_handler_func syscall_handler;
static syscall_handler_func
    *syscall_handlers[SYSCALL_NUM]; // array of all system calls

struct lock filesys_lock;

/* Projects 2 and later. */
void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

#ifdef VM
/* Project 3 and optionally project 4. */
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t mapping);
#endif

#ifdef FILESYS
/* Project 4 only. */
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char name[READDIR_MAX_LEN + 1]);
bool isdir (int fd);
int inumber (int fd);
#endif

static syscall_handler_func syscall_halt;
static syscall_handler_func syscall_exit;
static syscall_handler_func syscall_exec;
static syscall_handler_func syscall_wait;
static syscall_handler_func syscall_create;
static syscall_handler_func syscall_remove;
static syscall_handler_func syscall_open;
static syscall_handler_func syscall_filesize;
static syscall_handler_func syscall_read;
static syscall_handler_func syscall_write;
static syscall_handler_func syscall_seek;
static syscall_handler_func syscall_tell;
static syscall_handler_func syscall_close;

#ifdef VM
static syscall_handler_func syscall_mmap;
static syscall_handler_func syscall_munmap;
#endif

static int get_user_byte (const uint8_t *uaddr);
// static bool put_user_byte (uint8_t *udst, uint8_t byte);
static bool user_memory_check (void *uaddr, int bytes);
static bool user_string_memory_check (char *uaddr);

static struct file_descriptor *find_file_with_fd (struct list *list, int fd);

static void init_fd_pool (void);
static int get_fd (void);
static void recycle_fd (int old_fd);

#define MAX_FILE 128
static int fd_pool[MAX_FILE];
static int fd_pool_top;

static void
init_fd_pool (void)
{
  fd_pool_top = MAX_FILE - 1;
  for (int i = 0; i < MAX_FILE; i++)
    fd_pool[MAX_FILE - i - 1] = i + 2;
}

static int
get_fd (void)
{
  int result = -1;
  if (fd_pool_top >= 0)
    {
      result = fd_pool[fd_pool_top];
      fd_pool_top--;
    }
  return result;
}

static void
recycle_fd (int old_fd)
{
  ASSERT (old_fd < MAX_FILE + 2);
  ASSERT (fd_pool_top + 1 < MAX_FILE);
  fd_pool_top++;
  fd_pool[fd_pool_top] = old_fd;
}

void
halt (void)
{
  shutdown_power_off ();
}

int
valid_fd_num (void)
{
  return fd_pool_top;
}

void
exit (int status)
{
  thread_current ()->exit_status = status;
  thread_exit ();
}

pid_t
exec (const char *file)
{
  return process_execute (file);
}

int
wait (pid_t process)
{
  return process_wait (process);
}

bool
create (const char *file, unsigned initial_size)
{
  bool result = false;
  lock_acquire (&filesys_lock);
  result = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return result;
}

bool
remove (const char *file)
{
  bool result = false;
  lock_acquire (&filesys_lock);
  result = filesys_remove (file);
  lock_release (&filesys_lock);
  return result;
}

int
open (const char *file_name)
{
  struct file *file = NULL;
  struct file_descriptor *file_opened;
  // file_opened = palloc_get_page (0);
  file_opened = malloc (sizeof (struct file_descriptor));
  if (file_opened == NULL)
    return -1;
  lock_acquire (&filesys_lock);
  file = filesys_open (file_name);
  lock_release (&filesys_lock);
  if (file == NULL)
    return -1;
  else
    {
      int new_fd = get_fd ();
      // Kernel can open MAX_FILE files in total at most
      if (new_fd < 0)
        return -1;
      lock_acquire (&filesys_lock);
      file_opened->fd = new_fd;
      file_opened->file = file;
      list_push_back (&thread_current ()->file_list, &file_opened->file_elem);
      lock_release (&filesys_lock);
      return file_opened->fd;
    }
}

int
filesize (int fd)
{
  struct file_descriptor *f = NULL;
  int result = 0;
  lock_acquire (&filesys_lock);
  f = find_file_with_fd (&thread_current ()->file_list, fd);
  if (f == NULL)
    {
      lock_release (&filesys_lock);
      exit (-1);
    }
  result = file_length (f->file);
  lock_release (&filesys_lock);
  return result;
}

int
read (int fd, void *buffer, unsigned length)
{
  if (fd == STDIN)
    {
      lock_acquire (&filesys_lock);
      for (unsigned i = 0; i < length; i++)
        *((char *)(buffer + i)) = input_getc ();
      lock_release (&filesys_lock);
      return length;
    }
  else
    {
      struct file_descriptor *f = NULL;
      int result = -1;
      lock_acquire (&filesys_lock);
      f = find_file_with_fd (&thread_current ()->file_list, fd);

      if (f == NULL)
        {
          lock_release (&filesys_lock);
          exit (-1);
        }
      result = file_read (f->file, buffer, length);
      lock_release (&filesys_lock);
      return result;
    }
}

int
write (int fd, const void *buffer, unsigned length)
{
  if (fd == STDOUT)
    {
      lock_acquire (&filesys_lock);
      putbuf ((char *)buffer, length);
      lock_release (&filesys_lock);
      return (int)length;
    }
  else
    {
      struct file_descriptor *f = NULL;
      int result = -1;
      lock_acquire (&filesys_lock);
      f = find_file_with_fd (&thread_current ()->file_list, fd);

      if (f == NULL)
        {
          lock_release (&filesys_lock);
          exit (-1);
        }
      result = file_write (f->file, buffer, length);
      lock_release (&filesys_lock);
      return result;
    }
}

void
seek (int fd, unsigned position)
{
  struct file_descriptor *f = NULL;
  lock_acquire (&filesys_lock);
  f = find_file_with_fd (&thread_current ()->file_list, fd);
  if (f == NULL)
    {
      lock_release (&filesys_lock);
      exit (-1);
    }
  file_seek (f->file, position);
  lock_release (&filesys_lock);
}

unsigned
tell (int fd)
{
  struct file_descriptor *f = NULL;
  unsigned result = 0;
  lock_acquire (&filesys_lock);
  f = find_file_with_fd (&thread_current ()->file_list, fd);
  if (f == NULL)
    {
      lock_release (&filesys_lock);
      exit (-1);
    }
  result = file_tell (f->file);
  lock_release (&filesys_lock);
  return result;
}

void
close (int fd)
{
  /* User cannot close stdin or stdout. */
  if (fd == STDIN || fd == STDOUT)
    exit (-1);
  struct file_descriptor *f = NULL;
  lock_acquire (&filesys_lock);
  f = find_file_with_fd (&thread_current ()->file_list, fd);
  if (f == NULL)
    {
      lock_release (&filesys_lock);
      exit (-1);
    }
  else
    {
      int old_fd = f->fd;
      recycle_fd (old_fd);
      list_remove (&f->file_elem);
      file_close (f->file);
      // palloc_free_page (f);
      free (f);
      lock_release (&filesys_lock);
    }
}

#ifdef VM
static void init_mmapid_pool (void);
static int get_mmapid (void);
static void recycle_mmapid (int old_mmapid);

#define MAX_MMAPID 128
static int mmapid_pool[MAX_MMAPID];
static int mmapid_pool_top;

static void
init_mmapid_pool (void)
{
  mmapid_pool_top = MAX_MMAPID - 1;
  for (int i = 0; i < MAX_MMAPID; i++)
    mmapid_pool[MAX_MMAPID - i - 1] = i;
}

static int
get_mmapid (void)
{
  int result = -1;
  if (mmapid_pool_top >= 0)
    {
      result = mmapid_pool[mmapid_pool_top];
      mmapid_pool_top--;
    }
  return result;
}

static void
recycle_mmapid (int old_mmapid)
{
  ASSERT (old_mmapid < MAX_MMAPID);
  ASSERT (mmapid_pool_top + 1 < MAX_MMAPID);
  mmapid_pool_top++;
  mmapid_pool[mmapid_pool_top] = old_mmapid;
}

static bool is_mmap_overlap (void *addr, off_t file_size);
static struct mmap_entry *new_mmap_entry (void *addr, struct file *f,
                                          int page_count);
static void free_mmap_entry (struct mmap_entry *mmap_entry);

static bool
is_mmap_overlap (void *addr, off_t file_size)
{
  struct thread *t = thread_current ();

  for (; file_size >= 0; file_size -= PGSIZE)
    {
      if (sup_page_table_find_entry (&t->sup_page_table, addr) != NULL)
        return true;
      addr += PGSIZE;
    }

  return false;
}

static struct mmap_entry *
new_mmap_entry (void *addr, struct file *f, int page_count)
{
  struct mmap_entry *mmap_entry
      = (struct mmap_entry *)malloc (sizeof (struct mmap_entry));
  if (mmap_entry == NULL)
    return NULL;
  mmap_entry->addr = addr;
  mmap_entry->f = f;
  mmap_entry->page_count = page_count;
  mmap_entry->mmap_id = get_mmapid ();

  return mmap_entry;
}

static void
free_mmap_entry (struct mmap_entry *mmap_entry)
{
  struct thread *t = thread_current ();
  void *addr = mmap_entry->addr;
  int page_count = mmap_entry->page_count;
  for (int now_page = 0; now_page < page_count; now_page++)
    {
      struct sup_page_table_entry *sup_page_table_entry
          = sup_page_table_find_entry (&t->sup_page_table, addr);

      if (sup_page_table_entry != NULL)
        {
          sup_page_table_entry->dirty |= pagedir_is_dirty (t->pagedir, addr);
          /* If the page is dirty, we need write it back to file. */
          if (sup_page_table_entry->dirty)
            {
              lock_acquire (&filesys_lock);
              if (sup_page_table_entry->swap_index == NOT_IN_SWAP)
                {
                  file_write_at (sup_page_table_entry->file, addr,
                                 sup_page_table_entry->read_bytes,
                                 sup_page_table_entry->offset);
                }
              else if (sup_page_table_entry->from_file == false)
                {
                  void *tmp_kpage = palloc_get_page (PAL_ZERO);
                  /* Loaded page either be in swap partion or frame table. */
                  read_frame_from_block (sup_page_table_entry, tmp_kpage,
                                         sup_page_table_entry->swap_index);
                  file_write_at (sup_page_table_entry->file, tmp_kpage,
                                 sup_page_table_entry->read_bytes,
                                 sup_page_table_entry->offset);
                }
              else
                {
                  /* Mapped memory not be accessed actually. */
                  ASSERT (sup_page_table_entry->from_file == true);
                }
              lock_release (&filesys_lock);
            }

          /* If this page is present, we should delete it. */
          if (sup_page_table_entry->frame_table_entry != NULL)
            {
              free_frame_table_entry (
                  sup_page_table_entry->frame_table_entry,
                  sup_page_table_entry->frame_table_entry->frame_addr);
              pagedir_clear_page (thread_current ()->pagedir,
                                  sup_page_table_entry->addr);
            }

          /* Delete it from supplementary page table. */
          hash_delete (&t->sup_page_table, &sup_page_table_entry->elem);
        }
      else
        {
          PANIC ("mapped memory must be in supplementary page table.");
        }

      addr += PGSIZE;
    }

  lock_acquire (&filesys_lock);
  file_close (mmap_entry->f);
  lock_release (&filesys_lock);

  recycle_mmapid (mmap_entry->mmap_id);

  free (mmap_entry);
}

mapid_t
mmap (int fd, void *addr)
{
  /* 1. fd is STDIN or STDOUT.
     2. addr is not page aligned.
     3. addr is zero.
  */
  if (fd < 2 || (uint32_t)addr % PGSIZE != 0 || addr == NULL)
    return MAP_FAILED;

  struct file_descriptor *f
      = find_file_with_fd (&thread_current ()->file_list, fd);

  off_t file_size = 0;

  /* File size must greater than zero. */
  if (f == NULL || (file_size = file_length (f->file)) <= 0)
    return MAP_FAILED;

  lock_acquire (&filesys_lock);
  struct file *reopened_file = file_reopen (f->file);
  lock_release (&filesys_lock);

  ASSERT (file_size == file_length (reopened_file));

  if (reopened_file == NULL)
    return MAP_FAILED;

  /* Check whether the mmap is overlapping with other mapped memory. */
  if (is_mmap_overlap (addr, file_size))
    return MAP_FAILED;

  uint32_t read_bytes = file_size;
  uint32_t zero_bytes = (PGSIZE - file_size % PGSIZE) % PGSIZE;
  int page_count = (read_bytes + zero_bytes) / PGSIZE;

  struct mmap_entry *mmap_entry
      = new_mmap_entry (addr, reopened_file, page_count);

  if (mmap_entry == NULL)
    return MAP_FAILED;

  if (!lazy_load_segment (reopened_file, 0, addr, read_bytes, zero_bytes, true,
                          true))
    {
      free (mmap_entry);
      return MAP_FAILED;
    }

  list_push_back (&thread_current ()->mmap_list, &mmap_entry->elem);
  return mmap_entry->mmap_id;
}

void
munmap (mapid_t mapping)
{
  struct thread *t = thread_current ();
  /* Iterate over the mmap list and unmap all corresponding entry */
  for (struct list_elem *e = list_begin (&t->mmap_list);
       e != list_end (&t->mmap_list); e = list_next (e))
    {
      struct mmap_entry *entry = list_entry (e, struct mmap_entry, elem);
      if (entry->mmap_id == mapping)
        {
          list_remove (e);
          free_mmap_entry (entry);
          return;
        }
    }
}
#endif

static void
syscall_halt (struct intr_frame *f UNUSED)
{
  halt ();
}

static void
syscall_exit (struct intr_frame *f)
{
  if (!user_memory_check (f->esp + 4, 4))
    exit (-1);
  int status = *((int *)(f->esp + 4));
  exit (status);
}

static void
syscall_exec (struct intr_frame *f)
{
  // check normal memory
  if (!user_memory_check (f->esp + 4, 4))
    exit (-1);

  // check string memory
  char *str = *((char **)(f->esp + 4));
  if (!user_string_memory_check (str))
    exit (-1);

  f->eax = exec (str);
}

static void
syscall_wait (struct intr_frame *f)
{
  if (!user_memory_check (f->esp + 4, 4))
    exit (-1);
  tid_t process = *((tid_t *)(f->esp + 4));
  f->eax = wait (process);
}

static void
syscall_create (struct intr_frame *f)
{
  if (!user_memory_check (f->esp + 4, 4 * 2))
    exit (-1);
  char *file = *((char **)(f->esp + 4));
  if (!user_string_memory_check (file))
    exit (-1);
  uint32_t initial_size = *((uint32_t *)(f->esp + 8));
  f->eax = create (file, initial_size);
}

static void
syscall_remove (struct intr_frame *f)
{
  if (!user_memory_check (f->esp + 4, 4))
    exit (-1);
  char *file = *((char **)(f->esp + 4));
  if (!user_string_memory_check (file))
    exit (-1);
  f->eax = remove (file);
}

static void
syscall_open (struct intr_frame *f)
{
  if (!user_memory_check (f->esp + 4, 4))
    exit (-1);
  char *file = *((char **)(f->esp + 4));
  if (!user_string_memory_check (file))
    exit (-1);
  f->eax = open (file);
}

static void
syscall_filesize (struct intr_frame *f)
{
  if (!user_memory_check (f->esp + 4, 4))
    exit (-1);
  int fd = *((int *)(f->esp + 4));
  f->eax = filesize (fd);
}

static void
syscall_read (struct intr_frame *f)
{
  if (!user_memory_check (f->esp + 4, 4 * 3))
    exit (-1);

  int fd = *((int *)(f->esp + 4));
  void *buffer = *((void **)(f->esp + 8));
  uint32_t size = *((uint32_t *)(f->esp + 12));

  if (!user_memory_check (buffer, size))
    exit (-1);

  f->eax = read (fd, buffer, size);
}

static void
syscall_write (struct intr_frame *f)
{
  // memory check
  if (!user_memory_check (f->esp + 4, 4 * 3))
    exit (-1);

  int fd = *((int *)(f->esp + 4));
  void *buffer = *((void **)(f->esp + 8));
  uint32_t size = *((uint32_t *)(f->esp + 12));

  if (!user_memory_check (buffer, size))
    exit (-1);

  f->eax = write (fd, buffer, size);
}

static void
syscall_seek (struct intr_frame *f)
{
  if (!user_memory_check (f->esp + 4, 4 * 2))
    exit (-1);

  int fd = *((int *)(f->esp + 4));
  uint32_t position = *((uint32_t *)(f->esp + 8));

  seek (fd, position);
}

static void
syscall_tell (struct intr_frame *f)
{
  if (!user_memory_check (f->esp + 4, 4))
    exit (-1);

  int fd = *((int *)(f->esp + 4));

  f->eax = tell (fd);
}

static void
syscall_close (struct intr_frame *f)
{
  if (!user_memory_check (f->esp + 4, 4))
    exit (-1);

  int fd = *((int *)(f->esp + 4));

  close (fd);
}

#ifdef VM
static void
syscall_mmap (struct intr_frame *f)
{
  if (!user_memory_check (f->esp + 4, 4 * 2))
    exit (-1);

  int fd = *((int *)(f->esp + 4));
  void *addr = *((void **)(f->esp + 8));

  f->eax = mmap (fd, addr);
}

static void
syscall_munmap (struct intr_frame *f)
{
  if (!user_memory_check (f->esp + 4, 4))
    exit (-1);

  mapid_t mapping = *((mapid_t *)(f->esp + 4));

  munmap (mapping);
}
#endif

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  // init dispatch info
  syscall_handlers[SYS_HALT] = &syscall_halt;
  syscall_handlers[SYS_EXIT] = &syscall_exit;
  syscall_handlers[SYS_EXEC] = &syscall_exec;
  syscall_handlers[SYS_WAIT] = &syscall_wait;
  syscall_handlers[SYS_CREATE] = &syscall_create;
  syscall_handlers[SYS_REMOVE] = &syscall_remove;
  syscall_handlers[SYS_OPEN] = &syscall_open;
  syscall_handlers[SYS_FILESIZE] = &syscall_filesize;
  syscall_handlers[SYS_READ] = &syscall_read;
  syscall_handlers[SYS_WRITE] = &syscall_write;
  syscall_handlers[SYS_SEEK] = &syscall_seek;
  syscall_handlers[SYS_TELL] = &syscall_tell;
  syscall_handlers[SYS_CLOSE] = &syscall_close;
#ifdef VM
  syscall_handlers[SYS_MMAP] = &syscall_mmap;
  syscall_handlers[SYS_MUNMAP] = &syscall_munmap;

  init_mmapid_pool ();
#endif
  // init filesys_lock
  lock_init (&filesys_lock);
  init_fd_pool ();
}

static void
syscall_handler (struct intr_frame *f)
{
  thread_current ()->during_syscall = true;
  thread_current ()->syscall_esp = NULL;
  if (!user_memory_check (f->esp, 4))
    exit (-1);
  thread_current ()->syscall_esp = f->esp;
  uint32_t syscall_num = *((uint32_t *)f->esp);
  if (syscall_num >= SYSCALL_NUM || syscall_handlers[syscall_num] == NULL)
    exit (-1);

  syscall_handlers[syscall_num](f);
  thread_current ()->syscall_esp = NULL;
  thread_current ()->during_syscall = false;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the true if successful, -1 if a segfault
   occurred. */
static int
get_user_byte (const uint8_t *uaddr)
{
  if (uaddr == NULL || !is_user_vaddr (uaddr) || uaddr < (uint8_t *)0x08048000)
    return -1;

  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
// static bool
// put_user_byte (uint8_t *udst, uint8_t byte)
// {
//   int error_code;
//   asm("movl $1f, %0; movb %b2, %1; 1:"
//       : "=&a"(error_code), "=m"(*udst)
//       : "q"(byte));
//   return error_code != -1;
// }

static bool
user_memory_check (void *uaddr, int bytes)
{
  for (int i = 0; i < bytes; i++)
    {
      if (get_user_byte ((uint8_t *)(uaddr + i)) == -1)
        {
          return false;
        }
    }
  return true;
}

static bool
user_string_memory_check (char *uaddr)
{
  for (int i = 0;; i++)
    {
      int value = get_user_byte ((uint8_t *)(uaddr + i));

      if (value == 0 || value == -1)
        {
          // value is equal to zero, string terminator
          // value is equal to minus one, memory error
          // intr_set_level (old_level);
          return value != -1;
        }
    }
  return true;
}

static struct file_descriptor *
find_file_with_fd (struct list *list, int fd)
{
  struct list_elem *e;
  for (e = list_begin (list); e != list_end (list); e = list_next (e))
    {
      struct file_descriptor *f
          = list_entry (e, struct file_descriptor, file_elem);
      if (fd == f->fd)
        return f;
    }
  return NULL;
}

void
find_thread_with_tid (struct thread *t, void *aux)
{
  struct find_thread *find_thread;
  find_thread = (struct find_thread *)aux;
  if (t->tid == find_thread->tid)
    {
      find_thread->t = t;
    }
}

void
find_process_with_pid (struct process_status *pcb, void *aux)
{
  struct find_process *find_process;
  find_process = (struct find_process *)aux;
  if (find_process->pid == pcb->pid)
    {
      find_process->pcb = pcb;
    }
}

void
child_process_foreach (struct thread *t, process_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&t->child_process_list);
       e != list_end (&t->child_process_list); e = list_next (e))
    {
      struct process_status *pcb
          = list_entry (e, struct process_status, process_elem);
      func (pcb, aux);
    }
}