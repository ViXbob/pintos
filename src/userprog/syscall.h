#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "filesys/file.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "userprog/process.h"

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
	struct dir *dir;
  struct list_elem file_elem;
};

/* Map region identifier. */
typedef int mapid_t;
#define MAP_FAILED ((mapid_t)-1)

struct mmap_entry
{
  mapid_t mmap_id;       /* Mmap identifier. */
  void *addr;            /* Maped memory starts at addr. */
  struct file *f;        /* f is mapped into memory. */
  int page_count;        /* Total page f occupies. */
  struct list_elem elem; /* List element for mmap list. */
};

void find_process_with_pid (struct process_status *pcb, void *aux);
void find_thread_with_tid (struct thread *t, void *aux);
void child_process_foreach (struct thread *t, process_action_func *func,
                            void *aux);

/* You should use synchronization to ensure that only one
   process at a time is executing file system code. */
int valid_fd_num (void);

#endif /* userprog/syscall.h */
