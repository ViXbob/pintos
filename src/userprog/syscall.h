#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

struct find_thread
{
  int tid;
  struct thread *t;
};

void find_thread_with_tid (struct thread *t, void *aux);

#endif /* userprog/syscall.h */
