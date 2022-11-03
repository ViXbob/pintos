#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
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

void
halt (void)
{
  // TODO
}

void
exit (int status)
{
  thread_exit();
}

pid_t
exec (const char *file)
{
  // TODO
}

int
wait (pid_t process)
{
  // TODO
}

bool
create (const char *file, unsigned initial_size)
{
  // TODO
}

bool
remove (const char *file)
{
  // TODO
}

int
open (const char *file)
{
  // TODO
}

int
filesize (int fd)
{
  // TODO
}

int
read (int fd, void *buffer, unsigned length)
{
  // TODO
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
      // todo
      return -1;
    }
}

void
seek (int fd, unsigned position)
{
  // TODO
}

unsigned
tell (int fd)
{
  // TODO
}

void
close (int fd)
{
  // TODO
}

static void
syscall_halt (struct intr_frame *f)
{
  // TODO
}

static void
syscall_exit (struct intr_frame *f)
{
  printf ("now is system write!\n");
  int status = *((int *)(f->esp + 4));
  exit (status);
}

static void
syscall_exec (struct intr_frame *f)
{
  // TODO
}

static void
syscall_wait (struct intr_frame *f)
{
  // TODO
}

static void
syscall_create (struct intr_frame *f)
{
  // TODO
}

static void
syscall_remove (struct intr_frame *f)
{
  // TODO
}

static void
syscall_open (struct intr_frame *f)
{
  // TODO
}

static void
syscall_filesize (struct intr_frame *f)
{
  // TODO
}

static void
syscall_read (struct intr_frame *f)
{
  // TODO
}

static void
syscall_write (struct intr_frame *f)
{
  printf ("now is system write!\n");
  int fd = *((int *)(f->esp + 4));
  void *buffer = *((void **)(f->esp + 8));
  uint32_t size = *((uint32_t *)(f->esp + 12));
  write (fd, buffer, size);
}

static void
syscall_seek (struct intr_frame *f)
{
  // TODO
}

static void
syscall_tell (struct intr_frame *f)
{
  // TODO
}

static void
syscall_close (struct intr_frame *f)
{
  // TODO
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
}

static void
syscall_handler (struct intr_frame *f)
{
  printf ("system call!\n");
  uint32_t syscall_num = *((uint32_t *)f->esp);
  if (syscall_num >= SYSCALL_NUM) 
    {
      exit(-1);
    }
  syscall_handlers[syscall_num](f);
  // if (*((uint32_t *)f->esp) == SYS_WRITE)  //     printf ("now is system write!\n");
  //     int fd = *((int *)(f->esp + 4));
  //     void *buffer = *((void **)(f->esp + 8));
  //     uint32_t size = *((uint32_t *)(f->esp + 12));
  //     write (fd, buffer, size);
  //   {
  //     printf ("now is system write!\n");
  //     int fd = *((int *)(f->esp + 4));
  //     void *buffer = *((void **)(f->esp + 8));
  //     uint32_t size = *((uint32_t *)(f->esp + 12));
  //     write (fd, buffer, size);
  //   }
  // printf ("system call number: %d\n", *((uint32_t *)f->esp));
  // printf ("fd: %d\n", *((int *)(f->esp + 4)));
  // printf ("buffer: %p\n", *((void **)(f->esp + 8)));
  // printf ("size: %d\n", *((uint32_t *)(f->esp + 12)));
  // thread_exit ();
}
