#include "filesys/inode.h"
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include <debug.h>
#include <list.h>
#include <round.h>
#include <stdio.h>
#include <string.h>

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define INODE_SINGLE_INDIRECT_NUM 1
#define INODE_DOUBLY_INDIRECT_NUM 1

#define INODE_DIRECT_NUM                                                      \
  (128 - 3 - INODE_SINGLE_INDIRECT_NUM - INODE_DOUBLY_INDIRECT_NUM)

#define INDIRECT_PER_BLOCK (BLOCK_SECTOR_SIZE / sizeof (block_sector_t))

/*
        1. sector < start + BLOCK_NUM_LEVEL0
        2. start + BLOCK_NUM_LEVEL0 <= sector < start + BLOCK_NUM_LEVEL1
        3. start + BLOCK_NUM_LEVEL1 <= sector < start + BLOCK_NUM_LEVEL2
        4. start + BLOCK_NUM_LEVEL2 <= sector
*/

#define BLOCK_NUM_LEVEL0 INODE_DIRECT_NUM
#define BLOCK_NUM_LEVEL1 (BLOCK_NUM_LEVEL0 + INDIRECT_PER_BLOCK)
#define BLOCK_NUM_LEVEL2                                                      \
  (BLOCK_NUM_LEVEL1 + INDIRECT_PER_BLOCK * INDIRECT_PER_BLOCK)
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  union
  {
    block_sector_t blocks[INODE_DIRECT_NUM + 2];
    struct
    {
      block_sector_t direct_blocks[INODE_DIRECT_NUM];
      block_sector_t single_indirect_block;
      block_sector_t doubly_indirect_block;
    };
  };
  off_t length;   /* File size in bytes. */
  bool is_dir;    /* is directory or not */
  unsigned magic; /* Magic number. */
};

struct indirect_inode_disk
{
  block_sector_t blocks[INDIRECT_PER_BLOCK];
};

/* Static zero data for initialize. */
static char zeros[BLOCK_SECTOR_SIZE];

void load_indirect_inode_disk (block_sector_t, struct indirect_inode_disk *);
bool recursive_create_inode (struct inode_disk *, size_t);
bool create_inode_one_sector (block_sector_t *, struct indirect_inode_disk *);
void recursive_close_inode (struct inode_disk *, size_t);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
{
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  if (pos < 0 || pos >= inode->data.length)
    return -1;
  size_t sector = pos / BLOCK_SECTOR_SIZE;

  if (sector < BLOCK_NUM_LEVEL0)
    return inode->data.direct_blocks[sector];

  if (sector < BLOCK_NUM_LEVEL1)
    {
      struct indirect_inode_disk indirect_inode_disk;
      load_indirect_inode_disk (inode->data.single_indirect_block,
                                &indirect_inode_disk);
      return indirect_inode_disk.blocks[sector - BLOCK_NUM_LEVEL0];
    }

  if (sector < BLOCK_NUM_LEVEL2)
    {
      struct indirect_inode_disk indirect_inode_disk;
      load_indirect_inode_disk (inode->data.doubly_indirect_block,
                                &indirect_inode_disk);
      sector -= BLOCK_NUM_LEVEL1;
      struct indirect_inode_disk doubly_indirect_inode_disk;
      load_indirect_inode_disk (
          indirect_inode_disk.blocks[sector / INDIRECT_PER_BLOCK],
          &doubly_indirect_inode_disk);
      return doubly_indirect_inode_disk.blocks[sector % INDIRECT_PER_BLOCK];
    }

  return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->is_dir = is_dir;
      disk_inode->magic = INODE_MAGIC;
      /* Recursively create inode. */
      if (recursive_create_inode (disk_inode, sectors))
        {
          /* If successing, write back to disk. */
          write_wrapper (fs_device, sector, disk_inode);
          success = true;
        }
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  read_wrapper (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      if (inode->removed)
        {
          free_map_release (inode->sector, 1);
          /* Recursively close inode. */
          recursive_create_inode (&inode->data,
                                  bytes_to_sectors (inode->data.length));
        }

      free (inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          read_wrapper (fs_device, sector_idx, buffer + bytes_read);
        }
      else
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          read_wrapper (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  if (offset + size < 0
      || (size_t)(offset + size - 1) >= BLOCK_NUM_LEVEL2 * BLOCK_SECTOR_SIZE)
    return 0;

  if (offset + size - 1 >= inode->data.length)
    {
      size_t sectors = bytes_to_sectors (offset + size);
      if (!recursive_create_inode (&inode->data, sectors))
        return 0;
      inode->data.length = offset + size;
      write_wrapper (fs_device, inode->sector, &inode->data);
    }

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          write_wrapper (fs_device, sector_idx, buffer + bytes_written);
        }
      else
        {
          /* We need a bounce buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            read_wrapper (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          write_wrapper (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

/* Returns whether this inode is a dir or not. */
bool
inode_is_dir (const struct inode *inode)
{
	return inode->data.is_dir;
}

void
load_indirect_inode_disk (block_sector_t sector,
                          struct indirect_inode_disk *indirect_inode_disk)
{
  read_wrapper (fs_device, sector, indirect_inode_disk);
}

bool
recursive_create_inode (struct inode_disk *inode_disk, size_t sectors)
{
  if (sectors <= BLOCK_NUM_LEVEL0)
    {
      for (size_t i = 0; i < sectors; i++)
        if (!create_inode_one_sector (&inode_disk->direct_blocks[i], NULL))
          return false;
    }
  else if (sectors <= BLOCK_NUM_LEVEL1)
    {
      if (!recursive_create_inode (inode_disk, BLOCK_NUM_LEVEL0))
        return false;
      sectors -= BLOCK_NUM_LEVEL0;
      /* Create block for single indirect pointer. */
      struct indirect_inode_disk indirect_inode_disk;
      if (!create_inode_one_sector (&inode_disk->single_indirect_block,
                                    &indirect_inode_disk))
        return false;
      for (size_t i = 0; i < sectors; i++)
        if (!create_inode_one_sector (&indirect_inode_disk.blocks[i], NULL))
          return false;
      /* Write back to disk. */
      write_wrapper (fs_device, inode_disk->single_indirect_block,
                     &indirect_inode_disk);
    }
  else if (sectors <= BLOCK_NUM_LEVEL2)
    {
      if (!recursive_create_inode (inode_disk, BLOCK_NUM_LEVEL1))
        return false;
      sectors -= BLOCK_NUM_LEVEL1;
      /* Create block for doubly indirect pointer. */
      struct indirect_inode_disk doubly_indirect_inode_disk;
      if (!create_inode_one_sector (&inode_disk->doubly_indirect_block,
                                    &doubly_indirect_inode_disk))
        return false;
      struct indirect_inode_disk indirect_inode_disk;
      for (size_t single_indirect_index = 0;
           single_indirect_index < INDIRECT_PER_BLOCK && sectors > 0;
           single_indirect_index++)
        {
          size_t current_sectors
              = sectors < INDIRECT_PER_BLOCK ? sectors : INDIRECT_PER_BLOCK;
          if (!create_inode_one_sector (
                  &doubly_indirect_inode_disk.blocks[single_indirect_index],
                  &indirect_inode_disk))
            return false;
          for (size_t i = 0; i < current_sectors; i++)
            if (!create_inode_one_sector (&indirect_inode_disk.blocks[i],
                                          NULL))
              return false;
          /* Write back. */
          write_wrapper (
              fs_device,
              doubly_indirect_inode_disk.blocks[single_indirect_index],
              &indirect_inode_disk);
          sectors -= current_sectors;
        }
      write_wrapper (fs_device, inode_disk->doubly_indirect_block,
                     &doubly_indirect_inode_disk);
    }
  else
    {
      return false;
    }
  return true;
}

bool
create_inode_one_sector (block_sector_t *sector,
                         struct indirect_inode_disk *indirect_inode_disk)
{
  /* inode data will be initialized to zero, so we should create it if sector
   * is zero. */
  if (*sector == 0)
    {
      if (!free_map_allocate (1, sector))
        return false;
      write_wrapper (fs_device, *sector, zeros);
    }

  /* if indirect_inode_disk is not null, we should load indirect pointer into
   * it. */
  if (indirect_inode_disk != NULL)
    load_indirect_inode_disk (*sector, indirect_inode_disk);

  return true;
}

void
recursive_close_inode (struct inode_disk *inode_disk, size_t sectors)
{
  if (sectors <= BLOCK_NUM_LEVEL0)
    {
      for (size_t i = 0; i < sectors; i++)
        free_map_release (inode_disk->direct_blocks[i], 1);
    }
  else if (sectors <= BLOCK_NUM_LEVEL1)
    {
      recursive_close_inode (inode_disk, BLOCK_NUM_LEVEL0);
      sectors -= BLOCK_NUM_LEVEL0;
      struct indirect_inode_disk indirect_inode_disk;
      load_indirect_inode_disk (inode_disk->single_indirect_block,
                                &indirect_inode_disk);
      for (size_t i = 0; i < sectors; i++)
        free_map_release (indirect_inode_disk.blocks[i], 1);
      free_map_release (inode_disk->single_indirect_block, 1);
    }
  else if (sectors <= BLOCK_NUM_LEVEL2)
    {
      recursive_close_inode (inode_disk, BLOCK_NUM_LEVEL1);
      sectors -= BLOCK_NUM_LEVEL1;
      /* Create block for doubly indirect pointer. */
      struct indirect_inode_disk doubly_indirect_inode_disk;
      load_indirect_inode_disk (inode_disk->doubly_indirect_block,
                                &doubly_indirect_inode_disk);
      struct indirect_inode_disk indirect_inode_disk;
      for (size_t single_indirect_index = 0;
           single_indirect_index < INDIRECT_PER_BLOCK && sectors > 0;
           single_indirect_index++)
        {
          size_t current_sectors
              = sectors < INDIRECT_PER_BLOCK ? sectors : INDIRECT_PER_BLOCK;
          load_indirect_inode_disk (
              doubly_indirect_inode_disk.blocks[single_indirect_index],
              &indirect_inode_disk);
          for (size_t i = 0; i < current_sectors; i++)
            free_map_release (indirect_inode_disk.blocks[i], 1);
          free_map_release (
              doubly_indirect_inode_disk.blocks[single_indirect_index], 1);
          sectors -= current_sectors;
        }
      free_map_release (inode_disk->doubly_indirect_block, 1);
    }
  else
    {
      ASSERT (false);
    }
}