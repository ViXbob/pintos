#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <list.h>

int process_execute (const char *file_name);
int process_wait (int pid);
void process_exit (void);
void process_activate (void);

struct process_status
{
  int pid;
  struct thread *t;
  struct thread *parent_thread;
  int exit_status;
  struct lock lock_exit_status;
  struct list_elem process_elem;
};

typedef void process_action_func (struct process_status *pcb, void *aux);

#endif /* userprog/process.h */
