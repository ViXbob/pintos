#include "userprog/syscall.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
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
void close (int fd);

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

struct file_descriptor
{
  int fd;
  struct file *file;
  // struct lock lock;
  struct list_elem file_elem;
};

static struct list file_list;
static int fd_pool;

static struct file_descriptor *find_file_with_fd (int fd);

/* You should use synchronization to ensure that only one
   process at a time is executing file system code. */
static struct lock filesys_lock;

void
halt (void)
{
  shutdown_power_off ();
}

void
exit (int status)
{
  struct thread *t = thread_current ();
  // check whether current thread can exit
  lock_acquire (&t->count_lock);
  if (t->child_count > 0)
    {
      // there is no need to wait for child processes
      // cond_wait (&t->condvar, &t->count_lock);
      struct list_elem *e;
      for (e = list_begin (&t->child_process_list);
           e != list_end (&t->child_process_list); e = list_next (e))
        {
          struct thread *child_process
              = list_entry (e, struct thread, process_elem);
          child_process->parent_thread = NULL;
        }
    }
  lock_release (&t->count_lock);

  if (t->parent_thread != NULL)
    {
      lock_acquire (&t->parent_thread->count_lock);
      list_remove (&t->process_elem);
      t->parent_thread->child_count--;
      // there is no need to wait for child processes
      // if (t->parent_thread->child_count == 0)
      //   cond_signal (&t->parent_thread->condvar,
      //                &t->parent_thread->count_lock);
      lock_release (&t->parent_thread->count_lock);
    }

  t->exit_status = status;
  // Print exit status.
  printf ("%s: exit(%d)\n", t->name, t->exit_status);
  lock_release (&t->exit_status_lock);
  if (t->parent_thread != NULL)
    {
      lock_acquire (&t->parent_thread->get_exit_status_lock);
      lock_release (&t->parent_thread->get_exit_status_lock);
    }
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
  return filesys_create (file, initial_size);
}

bool
remove (const char *file)
{
  return filesys_remove (file);
}

int
open (const char *file_name)
{
  struct file *file = filesys_open (file_name);
  struct file_descriptor *file_opened;
  if (file == NULL)
    return -1;
  else
    {
      file_opened = (struct file_descriptor *)malloc (
          sizeof (struct file_descriptor *));
      file_opened->fd = fd_pool;
      fd_pool++;
      file_opened->file = file;
      list_push_back (&file_list, &file_opened->file_elem);
      return file_opened->fd;
    }
}

int
filesize (int fd)
{
  struct file_descriptor *f = find_file_with_fd (fd);
  if (f == NULL)
    exit (-1);
  return file_length (f->file);
}

int
read (int fd, void *buffer, unsigned length)
{
  if (fd == STDIN)
    {
      for (unsigned i = 0; i < length; i++)
        *((char *)(buffer + i)) = input_getc ();
      return length;
    }
  else
    {
      struct file_descriptor *f = find_file_with_fd (fd);
      return file_read (f->file, buffer, length);
    }
}

int
write (int fd, const void *buffer, unsigned length)
{
  if (fd == STDOUT)
    {
      putbuf ((char *)buffer, length);
      return (int)length;
    }
  else
    {
      struct file_descriptor *f = find_file_with_fd (fd);
      return file_write (f->file, buffer, length);
    }
}

void
seek (int fd, unsigned position)
{
  struct file_descriptor *f = find_file_with_fd (fd);
  if (f == NULL)
    exit (-1);
  return file_seek (f->file, position);
}

unsigned
tell (int fd)
{
  struct file_descriptor *f = find_file_with_fd (fd);
  if (f == NULL)
    exit (-1);
  return file_tell (f->file);
}

void
close (int fd)
{
  struct file_descriptor *f = find_file_with_fd (fd);
  if (f == NULL)
    exit (-1);
  else
    {
      list_remove (&f->file_elem);
      file_close (f->file);
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
  lock_acquire (&filesys_lock);
  f->eax = create (file, initial_size);
  lock_release (&filesys_lock);
}

static void
syscall_remove (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 2))
    exit (-1);
  char *file = *((char **)(f->esp + 4));
  if (!user_string_memory_check (file))
    exit (-1);
  lock_acquire (&filesys_lock);
  f->eax = remove (file);
  lock_release (&filesys_lock);
}

static void
syscall_open (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 2))
    exit (-1);
  char *file = *((char **)(f->esp + 4));
  if (!user_string_memory_check (file))
    exit (-1);
  lock_acquire (&filesys_lock);
  f->eax = open (file);
  lock_release (&filesys_lock);
}

static void
syscall_filesize (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 2))
    exit (-1);
  int fd = *((int *)(f->esp + 4));
  lock_acquire (&filesys_lock);
  f->eax = filesize (fd);
  lock_release (&filesys_lock);
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

  lock_acquire (&filesys_lock);
  f->eax = read (fd, buffer, size);
  lock_release (&filesys_lock);
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

  lock_acquire (&filesys_lock);
  f->eax = write (fd, buffer, size);
  lock_release (&filesys_lock);
}

static void
syscall_seek (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 3))
    exit (-1);

  int fd = *((int *)(f->esp + 4));
  uint32_t position = *((uint32_t *)(f->esp + 8));

  lock_acquire (&filesys_lock);
  seek (fd, position);
  lock_release (&filesys_lock);
}

static void
syscall_tell (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 2))
    exit (-1);

  int fd = *((int *)(f->esp + 4));

  lock_acquire (&filesys_lock);
  f->eax = tell (fd);
  lock_release (&filesys_lock);
}

static void
syscall_close (struct intr_frame *f)
{
  if (!user_memory_check (f->esp, 4 * 2))
    exit (-1);

  int fd = *((int *)(f->esp + 4));

  lock_acquire (&filesys_lock);
  close (fd);
  lock_release (&filesys_lock);
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
  list_init (&file_list);
  // exclude STDIN / STDOUT
  fd_pool = 2;
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
  if (uaddr + bytes > PHYS_BASE || uaddr < (void *)0x08048000)
    {
      intr_set_level (old_level);
      return false;
    }

  for (int i = 0; i < bytes; i++)
    {
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
      if (((void *)uaddr + i) >= PHYS_BASE || (void *)(uaddr + i) < (void *)0x08048000)
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
find_file_with_fd (int fd)
{
  struct list_elem *e;
  for (e = list_begin (&file_list); e != list_end (&file_list);
       e = list_next (e))
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