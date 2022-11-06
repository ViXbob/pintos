#include "userprog/syscall.h"
#include "userprog/pagedir.h"
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
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t)-1)

/* Map region identifier. */
typedef int mapid_t;
#define MAP_FAILED ((mapid_t)-1)

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

/* Project 3 and optionally project 4. */
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t);

/* Project 4 only. */
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char name[READDIR_MAX_LEN + 1]);
bool isdir (int fd);
int inumber (int fd);

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
  ASSERT (fd_pool_top < MAX_FILE);
  fd_pool[fd_pool_top] = old_fd;
  fd_pool_top++;
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
  file_opened = palloc_get_page (0);
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
      palloc_free_page (f);
      lock_release (&filesys_lock);
    }
}

static void
syscall_halt (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 0))
    exit (-1);
  halt ();
}

static void
syscall_exit (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 2))
    exit (-1);
  int status = *((int *)(f->esp + 4));
  exit (status);
}

static void
syscall_exec (struct intr_frame *f)
{
  // check normal memory
  if (!user_memory_check (f->esp, 4 * 2))
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
  if (!user_memory_check (f->esp, 4 * 2))
    exit (-1);
  tid_t process = *((tid_t *)(f->esp + 4));
  f->eax = wait (process);
  // printf("syscall_wait result is %d\n", f->eax);
  // printf("next line to run %p.\n", f->eip);
  // printf("next line to 0x%08x\n", *(uint32_t *)(f->eip));
}

static void
syscall_create (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 3))
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
  if (!user_memory_check (f->esp, 4 * 2))
    exit (-1);
  char *file = *((char **)(f->esp + 4));
  if (!user_string_memory_check (file))
    exit (-1);
  f->eax = remove (file);
}

static void
syscall_open (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 2))
    exit (-1);
  char *file = *((char **)(f->esp + 4));
  if (!user_string_memory_check (file))
    exit (-1);
  f->eax = open (file);
}

static void
syscall_filesize (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 2))
    exit (-1);
  int fd = *((int *)(f->esp + 4));
  f->eax = filesize (fd);
}

static void
syscall_read (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 4))
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
  if (!user_memory_check (f->esp, 4 * 4))
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
  if (!user_memory_check (f->esp, 4 * 3))
    exit (-1);

  int fd = *((int *)(f->esp + 4));
  uint32_t position = *((uint32_t *)(f->esp + 8));

  seek (fd, position);
}

static void
syscall_tell (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 2))
    exit (-1);

  int fd = *((int *)(f->esp + 4));

  f->eax = tell (fd);
}

static void
syscall_close (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 2))
    exit (-1);

  int fd = *((int *)(f->esp + 4));

  close (fd);
}

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
  // init filesys_lock
  lock_init (&filesys_lock);
  // init file_list
  // list_init (&thread_current ()->file_list);
  // exclude STDIN / STDOUT
  init_fd_pool ();
}

static void
syscall_handler (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4))
    exit (-1);
  uint32_t syscall_num = *((uint32_t *)f->esp);
  if (syscall_num >= SYSCALL_NUM)
    exit (-1);
  syscall_handlers[syscall_num](f);
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the true if successful, -1 if a segfault
   occurred. */
static int
get_user_byte (const uint8_t *uaddr)
{
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
  enum intr_level old_level;
  old_level = intr_disable ();
  if (uaddr + bytes > PHYS_BASE)
    {
      intr_set_level (old_level);
      return false;
    }

  for (int i = 0; i < bytes; i++)
    {
      if (pagedir_get_page(thread_current()->pagedir, uaddr + i) == NULL)
        return false;
      if (get_user_byte ((uint8_t *)(uaddr + i)) == -1)
        {
          intr_set_level (old_level);
          return false;
        }
    }
  intr_set_level (old_level);
  return true;
}

static bool
user_string_memory_check (char *uaddr)
{
  enum intr_level old_level;
  old_level = intr_disable ();
  for (int i = 0;; i++)
    {
      if (((void *)uaddr + i) >= PHYS_BASE
          || pagedir_get_page(thread_current()->pagedir, uaddr + i) == NULL)
        {
          intr_set_level (old_level);
          return false;
        }
      int value = get_user_byte ((uint8_t *)(uaddr + i));
      if (value == 0 || value == -1)
        {
          // value is equal to zero, string terminator
          // value is equal to minus one, memory error
          intr_set_level (old_level);
          return value != -1;
        }
    }
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
      struct process_status *pcb = list_entry (e, struct process_status, process_elem);
      func (pcb, aux);
    }
}