#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include <list.h>
#include <stdio.h>
#include <string.h>

/* A directory. */
struct dir
{
  struct inode *inode; /* Backing store. */
  off_t pos;           /* Current position. */
};

/* A single directory entry. */
struct dir_entry
{
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
};

bool dir_add_self_entry (struct dir *dir);
bool dir_add_father_entry (struct dir *ch_dir, struct dir *fa_dir);
bool dir_is_valid (struct dir *dir);
bool dir_is_empty (struct dir *dir);

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t initial_size,
            block_sector_t father_sector, bool on_creating)
{
  if (!inode_create (sector, initial_size, true))
    return false;
  struct dir *dir = dir_open (inode_open (sector), true);
  struct dir *fa_dir = dir_open (inode_open (father_sector), on_creating);
  bool success
      = dir_add_self_entry (dir) && dir_add_father_entry (dir, fa_dir);
  free (dir);
  free (fa_dir);
  return success;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode, bool create)
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;

      /* Invalid dir. */
      if (!create && !dir_is_valid (dir))
        {
          inode_close (inode);
          free (dir);
          return NULL;
        }

      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL;
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR), false);
}

/* Open dir with path (exclude the last token), save the last into file_name */
struct dir *
dir_open_with_path (const char *name, char const **file_name)
{
  /* Empty file */
  if (*name == '\0')
    return NULL;
  struct dir *dir = NULL;
  struct inode *inode = NULL;
  if (*name == '/')
    {
      /* Absolute path */
      dir = dir_open_root ();
      /* Skip all leading / */
      /* Process cases like '///////...' */
      while (*name && *name == '/')
        ++name;
    }
  else
    {
      /* Relative path */
      struct thread *cur = thread_current ();
      /* Open the current working directory */
      dir = !cur->cwd ? dir_open_root () : dir_reopen (cur->cwd);
    }
  /* Invalid, the starting directory is NULL */
  if (!dir)
    return NULL;

  /* Loop through the path splited by '/' */
  for (const char *next_token = name;; name = next_token)
    {
      /* Split the path by '/' */
      while (*next_token && *next_token != '/')
        ++next_token;
      /* Reach the end, this is the last token */
      if (*next_token == '\0')
        {
          /* Then save the last token into file_name */
          *file_name = name;
          break;
        }
      /* Split current name */
      /* By utilizing C99 standard, which allows variable-length array */
      char cur_name[next_token - name + 1];
      memcpy (cur_name, name, next_token - name);
      /* Ensure this is a string by adding '\0' at the end */
      cur_name[next_token - name] = '\0';

      struct dir *next_dir = NULL;
      /* Failed to get file */
      if (!dir_lookup (dir, cur_name, &inode)
          || !(next_dir = dir_open (inode, false)))
        {
          /* Prevent memory leak */
          dir_close (dir);
          return NULL;
        }
      /* Close the current dir and move to the next */
      dir_close (dir);
      dir = next_dir;
      /* Skip the '/'s */
      while (*next_token && *next_token == '/')
        ++next_token;
    }
  /* Cannot open a removed dir */
  if (inode_is_removed (dir_get_inode (dir)))
    {
      /* Prevent memory leak */
      dir_close (dir);
      return NULL;
    }

  return dir;
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir)
{
  return dir_open (inode_reopen (dir->inode), false);
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir)
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir)
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name, struct dir_entry *ep,
        off_t *ofsp)
{
  struct dir_entry e;
  size_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use && !strcmp (name, e.name))
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name, struct inode **inode)
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector,
         bool create)
{
  struct dir_entry e;
  off_t ofs;

  if (dir == NULL || name == NULL || *name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* dir is not a valid dir. */
  if (!create && !dir_is_valid (dir))
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    return false;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  return inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name)
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  if (inode_is_dir (inode))
    {
      struct dir *ch_dir = dir_open (inode, false);
      bool is_empty = dir_is_empty (ch_dir);
      dir_close (dir);
      if (!is_empty)
        goto done;
    }

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  if (!dir_is_valid (dir))
    return false;

  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e)
    {
      dir->pos += sizeof e;
      if (e.in_use && !(!strcmp (e.name, "..") || !strcmp (e.name, ".")))
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        }
    }
  return false;
}

/* return value false, failed to add self dir.
 * return value true, succeed to add self dir. */
bool
dir_add_self_entry (struct dir *dir)
{
  if (dir == NULL)
    return false;
  return dir_add (dir, ".", inode_get_inumber (dir->inode), true);
}

/* Add father entry(dir) to dir.
 * return value false, failed to add father entry.
 * return value true, succeed to add father entry. */
bool
dir_add_father_entry (struct dir *ch_dir, struct dir *fa_dir)
{
  if (ch_dir == NULL || fa_dir == NULL)
    return false;
  return dir_add (ch_dir, "..", inode_get_inumber (fa_dir->inode), true);
}

/* Check whether dir is a valid dir or not.
 * 1. Corresponding inode must be a dir type.
 * 2. It should contain "." and "..".
 * Otherwise it is not a valid dir. */
bool
dir_is_valid (struct dir *dir)
{
  if (!inode_is_dir (dir->inode))
    return false;
  struct dir_entry dir_entry;
  /* Do not have ".". */
  if (!lookup (dir, ".", &dir_entry, NULL))
    return false;
  /* Corresponding "." dir is not pointer to its self. */
  if (dir_entry.inode_sector != inode_get_inumber (dir->inode))
    return false;
  /* Do not have "..". */
  if (!lookup (dir, "..", NULL, NULL))
    return false;
  return true;
}

bool
dir_is_empty (struct dir *dir)
{
  struct dir_entry e;
  off_t ofs = 0;
  for (; inode_read_at (dir->inode, &e, sizeof (e), ofs) == sizeof (e);
       ofs += sizeof (e))
    {
      /* Exclude self and parent */
      if (e.in_use && !(!strcmp (".", e.name) || !strcmp ("..", e.name)))
        return false;
    }
  return true;
}