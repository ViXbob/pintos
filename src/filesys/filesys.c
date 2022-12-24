#include "filesys/filesys.h"
#include "filesys/cache.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/thread.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>

/* Partition that contains the file system. */
/* represents the block device on which the file system is stored and is used
 * to read and write data to and from the device.*/
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

#if ENABLE_CACHE
  cache_init ();
#endif

  inode_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void)
{
#if ENABLE_CACHE
  cache_flush ();
#endif

  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir)
{
  block_sector_t inode_sector = 0;
  bool success = false;
  const char *file_name = NULL;
  struct dir *dir = dir_open_with_path (name, &file_name);
  if (is_dir)
    {
      success = (dir != NULL && free_map_allocate (1, &inode_sector)
                 && dir_create (inode_sector, initial_size,
                                inode_get_inumber (dir_get_inode (dir)), false)
                 && dir_add (dir, file_name, inode_sector, false));
    }
  else
    {
      success = (dir != NULL && free_map_allocate (1, &inode_sector)
                 && inode_create (inode_sector, initial_size, is_dir)
                 && dir_add (dir, file_name, inode_sector, false));
    }

  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  const char *file_name = NULL;
  /* Open the directory that contains the file */
  struct dir *dir = dir_open_with_path (name, &file_name);
  struct inode *inode = NULL;

	if (dir == NULL)
		return NULL;
	
	/* The name is not ending as "/". */
	if (file_name != NULL && strlen (file_name) > 0)
		{
			dir_lookup (dir, file_name, &inode);
			dir_close (dir);
		}
	else 
		inode = dir_get_inode (dir);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name)
{
  const char *file_name = NULL;
  /* Open the directory that contains the file */
	/* Potential bug: the name is ending with "/". */
  struct dir *dir = dir_open_with_path (name, &file_name);
  bool success = dir != NULL && dir_remove (dir, file_name);
  dir_close (dir);

  return success;
}

/* Change current working directory to dir. */
bool
filesys_chdir (const char *dir_name)
{
  const char *file_name = NULL;
  struct dir *dir = dir_open_with_path (dir_name, &file_name);
  if (dir == NULL)
    return false;
  if (file_name != NULL && strlen (file_name) > 0)
    {
      struct inode *inode = NULL;
      dir_lookup (dir, file_name, &inode);
			dir_close (dir);
			dir = dir_open (inode, false);
			if (dir == NULL)
				return false;
    }
	struct thread *t = thread_current ();
	/* Close cwd and release memory. */
	dir_close (t->cwd);
	t->cwd = dir;
	return true;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 0, ROOT_DIR_SECTOR, true))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
