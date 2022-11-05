#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"


void syscall_init (void);

struct find_thread
{
  int tid;
  struct thread *t;
};

struct find_process
{
  int pid;
  struct process_status *pcb;
};

struct file_descriptor
{
  int fd;
  struct file *file;
  struct list_elem file_elem;
};

void find_process_with_pid (struct process_status *pcb, void *aux);
void find_thread_with_tid (struct thread *t, void *aux);
void child_process_foreach (struct thread *t, process_action_func *func, void *aux);

/* You should use synchronization to ensure that only one
   process at a time is executing file system code. */
struct lock filesys_lock;

#endif /* userprog/syscall.h */
