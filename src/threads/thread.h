#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include "threads/fixed-point.h"
#include "threads/synch.h"
#include <debug.h>
#include <list.h>
#include <stdint.h>

/* States in a thread's life cycle. */
enum thread_status
{
  THREAD_RUNNING, /* Running thread. */
  THREAD_READY,   /* Not running but ready to run. */
  THREAD_BLOCKED, /* Waiting for an event to trigger. */
  THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */

/* Clamp priority into [PRIMIN, PRIMAX]. */
#define clamp_pri(pri)                                                        \
  ((pri) < PRI_MIN ? PRI_MIN : ((pri) > PRI_MAX ? PRI_MAX : (pri)))

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
{
  /* Owned by thread.c. */
  tid_t tid;                 /* Thread identifier. */
  enum thread_status status; /* Thread state. */
  char name[16];             /* Name (for debugging purposes). */
  uint8_t *stack;            /* Saved stack pointer. */
  int priority;              /* Priority. */
  struct list_elem allelem;  /* List element for all threads list. */

  /* Shared between thread.c and synch.c. */
  struct list_elem elem; /* List element. */

#ifdef USERPROG
  /* Owned by userprog/process.c. */
  uint32_t *pagedir; /* Page directory. */
#endif

  int64_t block_ticks;           /* Blocked ticks. */
  struct list_elem blocked_elem; /* List element for blocked list. */

  /* For priority donate. */
  struct list donate_list;           /* List for donator threads. */
  struct list_elem donate_elem;      /* List element for donate_list. */
  struct list_elem lock_donate_elem; /* List element for lock_donate_list. */
  struct thread *holder;             /* The thread current thread donate to. */
  int origin_priority;               /* Origin priority for priority donate. */

  /* For multilevel feedback queue scheduler. */
  fp recent_cpu; /* How much CPU time each process has received "recently". */
  int nice; /* Nice value that determines how "nice" the thread should be. */

  /* For user process. */
  int exit_status;                  /* Exit status. */
  struct lock exit_status_lock;     /* Lock for exit status. */
  struct lock get_exit_status_lock; /* Lock for getting exit status. */
  struct list child_process_list;   /* Child processes semaphore. */
  struct list_elem process_elem; /* Child processes semaphore list element. */
  int child_count;               /* Counter indicating hos many child processes
                                    are running.*/
  struct lock count_lock;        /* Lock for child processes counter. */
  struct condition condvar;      /* Conditional variable for signaling. */
  struct thread *parent_thread;  /* Parent thread. */

  /* Owned by thread.c. */
  unsigned magic; /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_block_with_ticks (int64_t blocked_ticks);
void thread_unblock (struct thread *);
void thread_unblock_check (int64_t ticks);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);
bool thread_cmp_priority (const struct list_elem *a, const struct list_elem *b,
                          void *aux);
bool donate_thread_cmp_priority (const struct list_elem *a,
                                 const struct list_elem *b, void *aux);

/* Function for mlfqs mode. */
int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);
void thread_update_load_avg (void);
void thread_update_recent_cpu (struct thread *t, void *aux);
void thread_update_priority (struct thread *t, void *aux);

#endif /* threads/thread.h */
