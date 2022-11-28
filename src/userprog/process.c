#include "userprog/process.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void parse_parameter (char *str, int *argc, char **argv);

extern struct lock filesys_lock;

#define MAX_PARAMETER 128
#define WORD_BYTE 4

/* Parse str into arguments. */
void
parse_parameter (char *str, int *argc, char **argv)
{
  char *token = NULL;
  ASSERT (str != NULL);

  for (token = strtok_r (str, " ", &str); token != NULL;
       token = strtok_r (NULL, " ", &str))
    {
      argv[*argc] = token;
      (*argc)++;
    }
}

struct para_passing
{
  char *fn_copy;
  struct semaphore *sema_fn_copy;
  struct process_status *pcb;
  struct semaphore *sema_pcb;
};

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  struct para_passing para_passing;
  char *fn_copy = NULL;
  char *process_name = NULL, *save_ptr = NULL;
  struct process_status *child_process = NULL;
  tid_t tid;
  struct semaphore sema_fn_copy;
  struct semaphore sema_pcb;

  /* Palloc memory for variable. */ 
  // child_process = palloc_get_page(PAL_ZERO);
  child_process = malloc (sizeof (struct process_status));
  if (child_process == NULL)
    goto palloc_failed;

  size_t file_name_length = strlen (file_name) + 15;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  // fn_copy = palloc_get_page (PAL_ZERO);
  fn_copy = malloc (file_name_length);
  if (fn_copy == NULL)
    goto palloc_failed;

  // process_name = palloc_get_page (PAL_ZERO);
  process_name = malloc (file_name_length);
  if (process_name == NULL)
    goto palloc_failed;

  /* Initialize semaphore & para passing. */
  sema_init (&sema_fn_copy, 0);
  sema_init (&sema_pcb, 0);
  para_passing.sema_fn_copy = &sema_fn_copy;
  para_passing.sema_pcb = &sema_pcb;
  para_passing.pcb = child_process;
  para_passing.fn_copy = fn_copy;
  child_process->parent_thread = thread_current ();

  /* Copy file name. */ 
  strlcpy (para_passing.fn_copy, file_name, file_name_length - 10);
  strlcpy (process_name, file_name, file_name_length - 10);

  /* Get process name. */
  process_name = strtok_r (process_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (process_name, PRI_DEFAULT, start_process,
                       &para_passing);

  if (tid == TID_ERROR)
    goto palloc_failed;

  /* Set pcb & wait pid to be set. */
  sema_down (para_passing.sema_pcb);
  /* child_process->pid = tid; */
  if (child_process->pid >= 0)
    list_push_back (&thread_current ()->child_process_list, &child_process->process_elem);
  else 
    goto palloc_failed;

  sema_down (para_passing.sema_fn_copy);
  // printf ("free fn_copy & process_name.\n");
  // free two temporary string
  // palloc_free_page (fn_copy);
  free (fn_copy);
  // palloc_free_page (process_name);
  free (process_name);

  return tid;

palloc_failed:
  // printf ("If palloc error, free all of them.\n");
  if (fn_copy != NULL) 
    // palloc_free_page (fn_copy);
    free (fn_copy);
  if (process_name != NULL)
    // palloc_free_page (process_name);
    free (process_name);
  if (child_process != NULL)
    // palloc_free_page (child_process);
    free (child_process);
  return TID_ERROR;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *para_passing_)
{
  struct para_passing *para_passing = para_passing_;
  struct intr_frame if_;
  bool success = false;

  lock_init (&para_passing->pcb->lock_exit_status);
  lock_acquire (&para_passing->pcb->lock_exit_status);
  para_passing->pcb->t = thread_current ();
  thread_current ()->pcb = para_passing->pcb;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  int argc = 0;
  // char **argv = (char**) palloc_get_page(PAL_ZERO);
  char **argv = (char**) malloc(MAX_PARAMETER * sizeof (char*));

  if (argv == NULL)
    {
      success = false;
      goto memory_error;
    }

  parse_parameter (para_passing->fn_copy, &argc, (char **)argv);

  ASSERT (argc > 0);
  ASSERT (argc <= MAX_PARAMETER);

  success = load (argv[0], &if_.eip, &if_.esp);

  if (!success)
    {
      thread_current ()->tid = TID_ERROR;
      goto memory_error;
    }

  // push arguments (string) into stack
  size_t total_length = 0;
  for (int index = argc - 1; index >= 0; index--)
    {
      size_t length = strlen (argv[index]);
      if_.esp -= (length + 1);
      strlcpy ((char *)if_.esp, argv[index], length + 1);
      // update argv from local adress to stack adress
      argv[index] = if_.esp;
      total_length += (length + 1);
    }
  size_t align_bytes = (WORD_BYTE - total_length % WORD_BYTE) % WORD_BYTE;
  while (align_bytes > 0)
    {
      if_.esp -= 1;
      *((uint8_t *)if_.esp) = 0;
      align_bytes--;
    }

  // push argument pointers into stack
  ASSERT (sizeof (char *) == WORD_BYTE);
  if_.esp -= sizeof (char *);
  *((char **)if_.esp) = NULL;
  for (int index = argc - 1; index >= 0; index--)
    {
      if_.esp -= sizeof (char *);
      *((char **)if_.esp) = argv[index];
    }
  // update argv from local adress to stack adress
  char **argv_stack_adress = (char **)if_.esp;

  // push argv into stack
  ASSERT (sizeof (char **) == WORD_BYTE);
  if_.esp -= sizeof (char **);
  *((char ***)if_.esp) = argv_stack_adress;

  // push argc into stack
  ASSERT (sizeof (int) == WORD_BYTE);
  if_.esp -= sizeof (int);
  *((int *)if_.esp) = argc;

  typedef void (*func_ptr_type) (void);

  // push return adress into stack
  ASSERT (sizeof (func_ptr_type) == WORD_BYTE);
  if_.esp -= sizeof (func_ptr_type);
  *(func_ptr_type *)if_.esp = NULL;


memory_error:
  if (argv != NULL)
    // palloc_free_page (argv);
    free (argv);

  para_passing->pcb->pid = thread_current ()->tid;

  sema_up (para_passing->sema_fn_copy);
  sema_up (para_passing->sema_pcb);

  /* If load failed, quit. */
  if (!success) {
    thread_current ()->exit_status = -1;
    thread_exit ();
  }
    

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct find_process find_process;
  int process_status;
  find_process.pid = child_tid;
  find_process.pcb = NULL;

  ATOM
    {
      child_process_foreach (thread_current (), &find_process_with_pid, (void *)&find_process);
    }

  // printf("%s in wait: %d\n", thread_name(), list_size (&thread_current ()->child_process_list));
  if (find_process.pcb == NULL)
    return -1;
  // printf("child process is %s, parent process is %s\n", find_thread.t->name, find_thread.t->parent_thread->name);
  lock_acquire (&find_process.pcb->lock_exit_status);
  process_status = find_process.pcb->exit_status;
  lock_release (&find_process.pcb->lock_exit_status);
  // Free child process's pcb & IMPORTANT !!!
  list_remove (&find_process.pcb->process_elem);
  // palloc_free_page (find_process.pcb);
  free (find_process.pcb);
  // printf("%s out wait: %d, child process status is %d\n", thread_name(), list_size (&thread_current ()->child_process_list), process_status);
  return process_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  lock_acquire (&filesys_lock);
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }
  
  t->code_file = file;
  file_deny_write (file);
  
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2
      || ehdr.e_machine != 3 || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr) || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *)mem_page, read_bytes,
                                 zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  lock_release (&filesys_lock);
  return success;
}

/* load() helpers. */

bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int)page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
