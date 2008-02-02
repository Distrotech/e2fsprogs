/*
 * ext_attr.c --- extended attribute blocks
 * 
 * Copyright (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
 *
 * Copyright (C) 2002 Theodore Ts'o.
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Public
 * License.
 * %End-Header%
 */

#include <stdio.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <time.h>
#include <errno.h>

#include "ext2_fs.h"
#include "ext2_ext_attr.h"

#include "ext2fs.h"

#define NAME_HASH_SHIFT 5
#define VALUE_HASH_SHIFT 16

/*
 * ext2_xattr_hash_entry()
 *
 * Compute the hash of an extended attribute.
 */
__u32 ext2fs_ext_attr_hash_entry(struct ext2_ext_attr_entry *entry, void *data)
{
	__u32 hash = 0;
	char *name = entry->e_name;
	int n;

	for (n = 0; n < entry->e_name_len; n++) {
		hash = (hash << NAME_HASH_SHIFT) ^
		       (hash >> (8*sizeof(hash) - NAME_HASH_SHIFT)) ^
		       *name++;
	}

	/* The hash needs to be calculated on the data in little-endian. */
	if (entry->e_value_block == 0 && entry->e_value_size != 0) {
		__u32 *value = (__u32 *)data;
		for (n = (entry->e_value_size + EXT2_EXT_ATTR_ROUND) >>
			 EXT2_EXT_ATTR_PAD_BITS; n; n--) {
			hash = (hash << VALUE_HASH_SHIFT) ^
			       (hash >> (8*sizeof(hash) - VALUE_HASH_SHIFT)) ^
			       ext2fs_le32_to_cpu(*value++);
		}
	}

	return hash;
}

#undef NAME_HASH_SHIFT
#undef VALUE_HASH_SHIFT

#define BLOCK_HASH_SHIFT 16
/*
 * Re-compute the extended attribute hash value after an entry has changed.
 */
static void ext2fs_attr_rehash(struct ext2_ext_attr_header *header,
			       struct ext2_ext_attr_entry *entry)
{
	struct ext2_ext_attr_entry *here;
	__u32 hash = 0;

	entry->e_hash = ext2fs_ext_attr_hash_entry(entry, (char *) header +
						   entry->e_value_offs);

	here = ENTRY(header+1);
	while (!EXT2_EXT_IS_LAST_ENTRY(here)) {
		if (!here->e_hash) {
			/* Block is not shared if an entry's hash value == 0 */
			hash = 0;
			break;
		}
		hash = (hash << BLOCK_HASH_SHIFT) ^
		       (hash >> (8*sizeof(hash) - BLOCK_HASH_SHIFT)) ^
		       here->e_hash;
		here = EXT2_EXT_ATTR_NEXT(here);
	}
	header->h_hash = hash;
}

errcode_t ext2fs_read_ext_attr(ext2_filsys fs, blk_t block, void *buf)
{
	errcode_t	retval;

	retval = io_channel_read_blk(fs->io, block, 1, buf);
	if (retval)
		return retval;
#ifdef EXT2FS_ENABLE_SWAPFS
	if ((fs->flags & (EXT2_FLAG_SWAP_BYTES|
			  EXT2_FLAG_SWAP_BYTES_READ)) != 0)
		ext2fs_swap_ext_attr(buf, buf, fs->blocksize, 1);
#endif
	return 0;
}

errcode_t ext2fs_write_ext_attr(ext2_filsys fs, blk_t block, void *inbuf)
{
	errcode_t	retval;
	char		*write_buf;
	char		*buf = NULL;

#ifdef EXT2FS_ENABLE_SWAPFS
	if ((fs->flags & EXT2_FLAG_SWAP_BYTES) ||
	    (fs->flags & EXT2_FLAG_SWAP_BYTES_WRITE)) {
		retval = ext2fs_get_mem(fs->blocksize, &buf);
		if (retval)
			return retval;
		write_buf = buf;
		ext2fs_swap_ext_attr(buf, inbuf, fs->blocksize, 1);
	} else
#endif
		write_buf = (char *) inbuf;
	retval = io_channel_write_blk(fs->io, block, 1, write_buf);
	if (buf)
		ext2fs_free_mem(&buf);
	if (!retval)
		ext2fs_mark_changed(fs);
	return retval;
}

/*
 * This function adjusts the reference count of the EA block.
 */
errcode_t ext2fs_adjust_ea_refcount(ext2_filsys fs, blk_t blk,
				    char *block_buf, int adjust,
				    __u32 *newcount)
{
	errcode_t	retval;
	struct ext2_ext_attr_header *header;
	char	*buf = 0;

	if ((blk >= fs->super->s_blocks_count) ||
	    (blk < fs->super->s_first_data_block))
		return EXT2_ET_BAD_EA_BLOCK_NUM;

	if (!block_buf) {
		retval = ext2fs_get_mem(fs->blocksize, &buf);
		if (retval)
			return retval;
		block_buf = buf;
	}

	retval = ext2fs_read_ext_attr(fs, blk, block_buf);
	if (retval)
		goto errout;

	header = BHDR(block_buf);
	if (header->h_magic != EXT2_EXT_ATTR_MAGIC)
		return EXT2_ET_EA_BAD_MAGIC;

	header->h_refcount += adjust;
	if (newcount)
		*newcount = header->h_refcount;

	retval = ext2fs_write_ext_attr(fs, blk, block_buf);
	if (retval)
		goto errout;

errout:
	if (buf)
		ext2fs_free_mem(&buf);
	return retval;
}

struct ext2_attr_info {
	int name_index;
	const char *name;
	const char *value;
	int value_len;
};

struct ext2_attr_search {
	struct ext2_ext_attr_entry *first;
	char *base;
	char *end;
	struct ext2_ext_attr_entry *here;
	int not_found;
};

struct ext2_attr_ibody_find {
	ext2_ino_t ino;
	struct ext2_attr_search s;
};

struct ext2_attr_block_find {
	struct ext2_attr_search s;
	char *block;
};

void ext2fs_attr_shift_entries(struct ext2_ext_attr_entry *entry,
			       int value_offs_shift, char *to,
			       char *from, int n)
{
	struct ext2_ext_attr_entry *last = entry;

	/* Adjust the value offsets of the entries */
	for (; !EXT2_EXT_IS_LAST_ENTRY(last); last = EXT2_EXT_ATTR_NEXT(last)) {
		if (!last->e_value_block && last->e_value_size) {
			last->e_value_offs = last->e_value_offs +
							value_offs_shift;
		}
	}
	/* Shift the entries by n bytes */
	memmove(to, from, n);
}

/*
 * This function returns the free space present in the inode or the EA block.
 * total is number of bytes taken up by the EA entries and is used to shift the
 * EAs in ext2fs_expand_extra_isize().
 */
int ext2fs_attr_free_space(struct ext2_ext_attr_entry *last,
			   int *min_offs, char *base, int *total)
{
	for (; !EXT2_EXT_IS_LAST_ENTRY(last); last = EXT2_EXT_ATTR_NEXT(last)) {
		*total += EXT2_EXT_ATTR_LEN(last->e_name_len);
		if (!last->e_value_block && last->e_value_size) {
			int offs = last->e_value_offs;
			if (offs < *min_offs)
				*min_offs = offs;
		}
	}

	return (*min_offs - ((char *)last - base) - sizeof(__u32));
}

static errcode_t ext2fs_attr_check_names(struct ext2_ext_attr_entry *entry,
					 char *end)
{
	while (!EXT2_EXT_IS_LAST_ENTRY(entry)) {
		struct ext2_ext_attr_entry *next = EXT2_EXT_ATTR_NEXT(entry);
		if ((char *)next >= end)
			return EXT2_ET_EA_BAD_ENTRIES;
		entry = next;
	}
	return 0;
}

static errcode_t ext2fs_attr_find_entry(struct ext2_ext_attr_entry **pentry,
					int name_index, const char *name,
					int size, int sorted)
{
	struct ext2_ext_attr_entry *entry;
	int name_len;
	int cmp = 1;

	if (name == NULL)
		return EXT2_ET_EA_BAD_NAME;

	name_len = strlen(name);
	entry = *pentry;
	for (; !EXT2_EXT_IS_LAST_ENTRY(entry);
		entry = EXT2_EXT_ATTR_NEXT(entry)) {
		cmp = name_index - entry->e_name_index;
		if (!cmp)
			cmp = name_len - entry->e_name_len;
		if (!cmp)
			cmp = memcmp(name, entry->e_name, name_len);
		if (cmp <= 0 && (sorted || cmp == 0))
			break;
	}
	*pentry = entry;

	return cmp ? EXT2_ET_EA_NAME_NOT_FOUND : 0;
}

static errcode_t ext2fs_attr_block_find(ext2_filsys fs,struct ext2_inode *inode,
					struct ext2_attr_info *i,
					struct ext2_attr_block_find *bs)
{
	struct ext2_ext_attr_header *header;
	errcode_t error;

	if (inode->i_file_acl) {
		/* The inode already has an extended attribute block. */
		error = ext2fs_get_mem(fs->blocksize, &bs->block);
		if (error)
			return error;
		error = ext2fs_read_ext_attr(fs, inode->i_file_acl, bs->block);
		if (error)
			goto cleanup;

		header = BHDR(bs->block);
		if (header->h_magic != EXT2_EXT_ATTR_MAGIC) {
			error = EXT2_ET_EA_BAD_MAGIC;
			goto cleanup;
		}

		/* Find the named attribute. */
		bs->s.base = bs->block;
		bs->s.first = (struct ext2_ext_attr_entry *)(header + 1);
		bs->s.end = bs->block + fs->blocksize;
		bs->s.here = bs->s.first;
		error = ext2fs_attr_find_entry(&bs->s.here, i->name_index,
					       i->name, fs->blocksize, 1);
		if (error && error != EXT2_ET_EA_NAME_NOT_FOUND)
			goto cleanup;
		bs->s.not_found = error;
	}
	error = 0;

cleanup:
	if (error && bs->block)
		ext2fs_free_mem(&bs->block);
	return error;
}

static errcode_t ext2fs_attr_ibody_find(ext2_filsys fs,
					struct ext2_inode_large *inode,
					struct ext2_attr_info *i,
					struct ext2_attr_ibody_find *is)
{
	__u32 *eamagic;
	char *start;
	errcode_t error;

	if (EXT2_INODE_SIZE(fs->super) == EXT2_GOOD_OLD_INODE_SIZE)
		return 0;

	if (inode->i_extra_isize == 0)
		return 0;
	eamagic = IHDR(inode);

	start = (char *) inode + EXT2_GOOD_OLD_INODE_SIZE +
				inode->i_extra_isize + sizeof(__u32);
	is->s.first = (struct ext2_ext_attr_entry *) start;
	is->s.base = start;
	is->s.here = is->s.first;
	is->s.end = (char *) inode + EXT2_INODE_SIZE(fs->super);
	if (*eamagic == EXT2_EXT_ATTR_MAGIC) {
		error = ext2fs_attr_check_names((struct ext2_ext_attr_entry *)
						start, is->s.end);
		if (error)
			return error;
		/* Find the named attribute. */
		error = ext2fs_attr_find_entry(&is->s.here, i->name_index,
					       i->name, is->s.end -
					       (char *)is->s.base, 0);
		if (error && error != EXT2_ET_EA_NAME_NOT_FOUND)
			return error;
		is->s.not_found = error;
	}

	return 0;
}

static errcode_t ext2fs_attr_set_entry(ext2_filsys fs, struct ext2_attr_info *i,
				       struct ext2_attr_search *s)
{
	struct ext2_ext_attr_entry *last;
	int free, min_offs = s->end - s->base, name_len = strlen(i->name);

	/* Compute min_offs and last. */
	for (last = s->first; !EXT2_EXT_IS_LAST_ENTRY(last);
	     last = EXT2_EXT_ATTR_NEXT(last)) {
		if (!last->e_value_block && last->e_value_size) {
			int offs = last->e_value_offs;

			if (offs < min_offs)
				min_offs = offs;
		}
	}
	free = min_offs - ((char *)last - s->base) - sizeof(__u32);

	if (!s->not_found) {
		if (!s->here->e_value_block && s->here->e_value_size) {
			int size = s->here->e_value_size;
			free += EXT2_EXT_ATTR_SIZE(size);
		}
		free += EXT2_EXT_ATTR_LEN(name_len);
	}
	if (i->value) {
		if (free < EXT2_EXT_ATTR_LEN(name_len) +
			   EXT2_EXT_ATTR_SIZE(i->value_len))
			return EXT2_ET_EA_NO_SPACE;
	}

	if (i->value && s->not_found) {
		/* Insert the new name. */
		int size = EXT2_EXT_ATTR_LEN(name_len);
		int rest = (char *)last - (char *)s->here + sizeof(__u32);

		memmove((char *)s->here + size, s->here, rest);
		memset(s->here, 0, size);
		s->here->e_name_index = i->name_index;
		s->here->e_name_len = name_len;
		memcpy(s->here->e_name, i->name, name_len);
	} else {
		if (!s->here->e_value_block && s->here->e_value_size) {
			char *first_val = s->base + min_offs;
			int offs = s->here->e_value_offs;
			char *val = s->base + offs;
			int size = EXT2_EXT_ATTR_SIZE(s->here->e_value_size);

			if (i->value &&
			    size == EXT2_EXT_ATTR_SIZE(i->value_len)) {
				/* The old and the new value have the same
				   size. Just replace. */
				s->here->e_value_size = i->value_len;
				memset(val + size - EXT2_EXT_ATTR_PAD, 0,
				       EXT2_EXT_ATTR_PAD); /* Clear pad bytes */
				memcpy(val, i->value, i->value_len);
				return 0;
			}

			/* Remove the old value. */
			memmove(first_val + size, first_val, val - first_val);
			memset(first_val, 0, size);
			s->here->e_value_size = 0;
			s->here->e_value_offs = 0;
			min_offs += size;

			/* Adjust all value offsets. */
			last = s->first;
			while (!EXT2_EXT_IS_LAST_ENTRY(last)) {
				int o = last->e_value_offs;

				if (!last->e_value_block &&
				    last->e_value_size && o < offs)
					last->e_value_offs = o + size;
				last = EXT2_EXT_ATTR_NEXT(last);
			}
		}
		if (!i->value) {
			/* Remove the old name. */
			int size = EXT2_EXT_ATTR_LEN(name_len);

			last = ENTRY((char *)last - size);
			memmove((char *)s->here, (char *)s->here + size,
				(char *)last - (char *)s->here + sizeof(__u32));
			memset(last, 0, size);
		}
	}

	if (i->value) {
		/* Insert the new value. */
		s->here->e_value_size = i->value_len;
		if (i->value_len) {
			int size = EXT2_EXT_ATTR_SIZE(i->value_len);
			char *val = s->base + min_offs - size;

			s->here->e_value_offs = min_offs - size;
			memset(val + size - EXT2_EXT_ATTR_PAD, 0,
			       EXT2_EXT_ATTR_PAD); /* Clear the pad bytes. */
			memcpy(val, i->value, i->value_len);
		}
	}

	return 0;
}

static errcode_t ext2fs_attr_block_set(ext2_filsys fs, struct ext2_inode *inode,
				       struct ext2_attr_info *i,
				       struct ext2_attr_block_find *bs)
{
	struct ext2_attr_search *s = &bs->s;
	char *new_buf = NULL, *old_block = NULL;
	blk_t blk;
	int clear_flag = 0;
	errcode_t error;

	if (i->value && i->value_len > fs->blocksize)
		return EXT2_ET_EA_NO_SPACE;

	if (s->base) {
		if (BHDR(s->base)->h_refcount != 1) {
			int offset = (char *)s->here - bs->block;

			/* Decrement the refcount of the shared block */
			old_block = s->base;
			BHDR(s->base)->h_refcount -= 1;

			error = ext2fs_get_mem(fs->blocksize, &s->base);
			if (error)
				goto cleanup;
			clear_flag = 1;
			memcpy(s->base, bs->block, fs->blocksize);
			s->first = ENTRY(BHDR(s->base)+1);
			BHDR(s->base)->h_refcount = 1;
			s->here = ENTRY(s->base + offset);
			s->end = s->base + fs->blocksize;
		}
	} else {
		error = ext2fs_get_mem(fs->blocksize, &s->base);
		if (error)
			goto cleanup;
		clear_flag = 1;
		memset(s->base, 0, fs->blocksize);
		BHDR(s->base)->h_magic = EXT2_EXT_ATTR_MAGIC;
		BHDR(s->base)->h_blocks = 1;
		BHDR(s->base)->h_refcount = 1;
		s->first = ENTRY(BHDR(s->base)+1);
		s->here = ENTRY(BHDR(s->base)+1);
		s->end = s->base + fs->blocksize;
	}

	error = ext2fs_attr_set_entry(fs, i, s);
	if (error)
		goto cleanup;

	if (!EXT2_EXT_IS_LAST_ENTRY(s->first))
		ext2fs_attr_rehash(BHDR(s->base), s->here);

	if (!EXT2_EXT_IS_LAST_ENTRY(s->first)) {
		if (bs->block && bs->block == s->base) {
			/* We are modifying this block in-place */
			new_buf = bs->block;
			blk = inode->i_file_acl;
			error = ext2fs_write_ext_attr(fs, blk, s->base);
			if (error)
				goto cleanup;
		} else {
			/* We need to allocate a new block */
			error = ext2fs_new_block(fs, 0, 0, &blk);
			if (error)
				goto cleanup;
			ext2fs_block_alloc_stats(fs, blk, +1);
			error = ext2fs_write_ext_attr(fs, blk, s->base);
			if (error)
				goto cleanup;
			new_buf = s->base;
			if (old_block) {
				BHDR(s->base)->h_refcount -= 1;
				error = ext2fs_write_ext_attr(fs,
							      inode->i_file_acl,
							      s->base);
				if (error)
					goto cleanup;
			}
		}
	}

	/* Update the i_blocks if we added a new EA block */
	if (!inode->i_file_acl && new_buf)
		inode->i_blocks += fs->blocksize / 512;
	/* Update the inode. */
	inode->i_file_acl = new_buf ? blk : 0;

cleanup:
	if (clear_flag)
		ext2fs_free_mem(&s->base);
	return 0;
}

static errcode_t ext2fs_attr_ibody_set(ext2_filsys fs,
				       struct ext2_inode_large *inode,
				       struct ext2_attr_info *i,
				       struct ext2_attr_ibody_find *is)
{
	__u32 *eamagic;
	struct ext2_attr_search *s = &is->s;
	errcode_t error;

	if (EXT2_INODE_SIZE(fs->super) == EXT2_GOOD_OLD_INODE_SIZE)
		return EXT2_ET_EA_NO_SPACE;

	error = ext2fs_attr_set_entry(fs, i, s);
	if (error)
		return error;

	eamagic = IHDR(inode);
	if (!EXT2_EXT_IS_LAST_ENTRY(s->first))
		*eamagic = EXT2_EXT_ATTR_MAGIC;
	else
		*eamagic = 0;

	return ext2fs_write_inode_full(fs, is->ino, (struct ext2_inode *)inode,
				       EXT2_INODE_SIZE(fs->super));
}


errcode_t ext2fs_attr_set(ext2_filsys fs, ext2_ino_t ino,
			  struct ext2_inode *inode,
			  int name_index, const char *name, const char *value,
			  int value_len, int flags)
{
	struct ext2_inode_large *inode_large = NULL;
	struct ext2_attr_info i = {
		.name_index = name_index,
		.name = name,
		.value = value,
		.value_len = value_len,
	};
	struct ext2_attr_ibody_find is = {
		.ino = ino,
		.s = { .not_found = -ENODATA, },
	};
	struct ext2_attr_block_find bs = {
		.s = { .not_found = -ENODATA, },
	};
	errcode_t error;

	if (!name)
		return EXT2_ET_EA_BAD_NAME;
	if (strlen(name) > 255)
		return EXT2_ET_EA_NAME_TOO_BIG;

	if (EXT2_INODE_SIZE(fs->super) > EXT2_GOOD_OLD_INODE_SIZE) {
		inode_large = (struct ext2_inode_large *)inode;

		error = ext2fs_attr_ibody_find(fs, inode_large, &i, &is);
		if (error)
			goto cleanup;
	}
	if (is.s.not_found) {
		error = ext2fs_attr_block_find(fs, inode, &i, &bs);
		if (error)
			goto cleanup;
	}

	if (is.s.not_found && bs.s.not_found) {
		error = EXT2_ET_EA_NAME_NOT_FOUND;
		if (flags & XATTR_REPLACE)
			goto cleanup;
		error = 0;
		if (!value)
			goto cleanup;
	} else {
		error = EXT2_ET_EA_NAME_EXISTS;
		if (flags & XATTR_CREATE)
			goto cleanup;
	}

	if (!value) {
		if (!is.s.not_found &&
		    (EXT2_INODE_SIZE(fs->super) > EXT2_GOOD_OLD_INODE_SIZE))
			error = ext2fs_attr_ibody_set(fs, inode_large, &i, &is);
		else if (!bs.s.not_found)
			error = ext2fs_attr_block_set(fs, inode, &i, &bs);
	} else {
		if (EXT2_INODE_SIZE(fs->super) > EXT2_GOOD_OLD_INODE_SIZE)
			error = ext2fs_attr_ibody_set(fs, inode_large, &i, &is);
		if (!error && !bs.s.not_found) {
			i.value = NULL;
			error = ext2fs_attr_block_set(fs, inode, &i, &bs);
		} else if (error == EXT2_ET_EA_NO_SPACE) {
			error = ext2fs_attr_block_set(fs, inode, &i, &bs);
			if (error)
				goto cleanup;
			if (!is.s.not_found) {
				i.value = NULL;
				if (EXT2_INODE_SIZE(fs->super) >
				    EXT2_GOOD_OLD_INODE_SIZE)
					error = ext2fs_attr_ibody_set(fs,
							inode_large, &i, &is);
			}
		}
	}

cleanup:
	return error;
}

static errcode_t ext2fs_attr_check_block(ext2_filsys fs, char *buffer)
{
	if (BHDR(buffer)->h_magic != (EXT2_EXT_ATTR_MAGIC) ||
	    BHDR(buffer)->h_blocks != 1)
		return EXT2_ET_EA_BAD_MAGIC;

	return ext2fs_attr_check_names((struct ext2_ext_attr_entry *)
				       (BHDR(buffer) + 1),
				       buffer + fs->blocksize);
}

static errcode_t ext2fs_attr_block_get(ext2_filsys fs, struct ext2_inode *inode,
				       int name_index, const char *name,
				       void *buffer, size_t buffer_size,
				       int *easize)
{
	struct ext2_ext_attr_header *header = NULL;
	struct ext2_ext_attr_entry *entry;
	char *block_buf = NULL;
	errcode_t error;

	error = EXT2_ET_EA_NAME_NOT_FOUND;
	if (!inode->i_file_acl)
		goto cleanup;

	error = ext2fs_get_mem(fs->blocksize, &block_buf);
	if (error)
		return error;
	error = ext2fs_read_ext_attr(fs, inode->i_file_acl, block_buf);
	if (error)
		goto cleanup;

	error = ext2fs_attr_check_block(fs, block_buf);
	if (error)
		goto cleanup;

	header = BHDR(block_buf);
	entry = (struct ext2_ext_attr_entry *)(header+1);
	error = ext2fs_attr_find_entry(&entry, name_index, name,
				       fs->blocksize, 1);
	if (error)
		goto cleanup;
	if (easize)
		*easize = entry->e_value_size;
	if (buffer) {
		error = EXT2_ET_EA_TOO_BIG;
		if (entry->e_value_size > buffer_size)
			goto cleanup;
		memcpy(buffer, block_buf + entry->e_value_offs,
		       entry->e_value_size);
	}

cleanup:
	if (block_buf)
		ext2fs_free_mem (&block_buf);
	return error;
}

static errcode_t ext2fs_attr_ibody_get(ext2_filsys fs,
				       struct ext2_inode_large *inode,
				       int name_index, const char *name,
				       void *buffer, size_t buffer_size,
				       int *easize)
{
	struct ext2_ext_attr_entry *entry;
	int error;
	char *end, *start;
	__u32 *eamagic;

	if (EXT2_INODE_SIZE(fs->super) == EXT2_GOOD_OLD_INODE_SIZE)
		return EXT2_ET_EA_NAME_NOT_FOUND;

	eamagic = IHDR(inode);
	error = ext2fs_attr_check_block(fs, buffer);
	if (error)
		return error;

	start = (char *)inode + EXT2_GOOD_OLD_INODE_SIZE +
				inode->i_extra_isize + sizeof(__u32);
	entry = (struct ext2_ext_attr_entry *)start;
	end = (char *)inode + EXT2_INODE_SIZE(fs->super);
	error = ext2fs_attr_check_names(entry, end);
	if (error)
		goto cleanup;
	error = ext2fs_attr_find_entry(&entry, name_index, name,
				       end - (char *)entry, 0);
	if (error)
		goto cleanup;
	if (easize)
		*easize = entry->e_value_size;
	if (buffer) {
		error = EXT2_ET_EA_TOO_BIG;
		if (entry->e_value_size > buffer_size)
			goto cleanup;
		memcpy(buffer, start + entry->e_value_offs,entry->e_value_size);
	}

cleanup:
	return error;
}


errcode_t ext2fs_attr_get(ext2_filsys fs, struct ext2_inode *inode,
			  int name_index, const char *name, char *buffer,
			  size_t buffer_size, int *easize)
{
	errcode_t error;

	error = ext2fs_attr_ibody_get(fs, (struct ext2_inode_large *)inode,
				      name_index, name, buffer, buffer_size,
				      easize);
	if (error == EXT2_ET_EA_NAME_NOT_FOUND)
		error = ext2fs_attr_block_get(fs, inode, name_index, name,
					      buffer, buffer_size, easize);

	return error;
}

char *ext2_attr_index_prefix[] = {
	[EXT2_ATTR_INDEX_USER] = EXT2_ATTR_INDEX_USER_PREFIX,
	[EXT2_ATTR_INDEX_POSIX_ACL_ACCESS] = EXT2_ATTR_INDEX_POSIX_ACL_ACCESS_PREFIX,
	[EXT2_ATTR_INDEX_POSIX_ACL_DEFAULT] = EXT2_ATTR_INDEX_POSIX_ACL_DEFAULT_PREFIX,
	[EXT2_ATTR_INDEX_TRUSTED] = EXT2_ATTR_INDEX_TRUSTED_PREFIX,
	[EXT2_ATTR_INDEX_LUSTRE] = EXT2_ATTR_INDEX_LUSTRE_PREFIX,
	[EXT2_ATTR_INDEX_SECURITY] = EXT2_ATTR_INDEX_SECURITY_PREFIX,
	NULL
};

int ext2fs_attr_get_next_attr(struct ext2_ext_attr_entry *entry, int name_index,
			      char *buffer, int buffer_size, int start)
{
	const int prefix_len = strlen(ext2_attr_index_prefix[name_index]);
	int total_len;

	if (!start && !EXT2_EXT_IS_LAST_ENTRY(entry))
		entry = EXT2_EXT_ATTR_NEXT(entry);

	for (; !EXT2_EXT_IS_LAST_ENTRY(entry);
	     entry = EXT2_EXT_ATTR_NEXT(entry)) {
		if (!name_index)
			break;
		if (name_index == entry->e_name_index)
			break;
	}
	if (EXT2_EXT_IS_LAST_ENTRY(entry))
		return 0;

	total_len = prefix_len + entry->e_name_len + 1;
	if (buffer && total_len <= buffer_size) {
		memcpy(buffer, ext2_attr_index_prefix[name_index], prefix_len);
		memcpy(buffer + prefix_len, entry->e_name, entry->e_name_len);
		buffer[prefix_len + entry->e_name_len] = '\0';
	}

	return total_len;
}

errcode_t ext2fs_expand_extra_isize(ext2_filsys fs, ext2_ino_t ino,
				    struct ext2_inode_large *inode,
				    int new_extra_isize, int *ret,
				    int *needed_size)
{
	struct ext2_inode *inode_buf = NULL;
	__u32 *eamagic = NULL;
	struct ext2_ext_attr_header *header = NULL;
	struct ext2_ext_attr_entry *entry = NULL, *last = NULL;
	struct ext2_attr_ibody_find is = {
		.ino = ino,
		.s = { .not_found = EXT2_ET_EA_NO_SPACE, },
	};
	struct ext2_attr_block_find bs = {
		.s = { .not_found = EXT2_ET_EA_NO_SPACE, },
	};
	char *start, *end, *block_buf = NULL, *buffer =NULL, *b_entry_name=NULL;
	int total_ino = 0, total_blk, free, offs, tried_min_extra_isize = 0;
	int s_min_extra_isize = fs->super->s_min_extra_isize;
	errcode_t error = 0;

	if (needed_size)
		*needed_size = new_extra_isize;
	error = ext2fs_get_mem(fs->blocksize, &block_buf);
	if (error)
		return error;

	if (inode == NULL) {
		error = ext2fs_get_mem(EXT2_INODE_SIZE(fs->super), &inode_buf);
		if (error)
			goto cleanup;

		error = ext2fs_read_inode_full(fs, ino, inode_buf,
					       EXT2_INODE_SIZE(fs->super));
		if (error)
			goto cleanup;

		inode = (struct ext2_inode_large *)inode_buf;
	}

retry:
	if (inode->i_extra_isize >= new_extra_isize)
		goto cleanup;

	eamagic = IHDR(inode);
	/* No extended attributes present */
	if (*eamagic != EXT2_EXT_ATTR_MAGIC) {
		memset((char *)inode + EXT2_GOOD_OLD_INODE_SIZE +
		       inode->i_extra_isize, 0,
		       EXT2_INODE_SIZE(fs->super) - EXT2_GOOD_OLD_INODE_SIZE -
		       inode->i_extra_isize);
		inode->i_extra_isize = new_extra_isize;
		if (needed_size)
			*needed_size = 0;
		goto write_inode;
	}

	start = (char *) inode + EXT2_GOOD_OLD_INODE_SIZE +
					inode->i_extra_isize + sizeof(__u32);
	end = (char *) inode + EXT2_INODE_SIZE(fs->super);
	last = entry = (struct ext2_ext_attr_entry *) start;
	offs = end - start;
	/* Consider space takenup by magic number */
	total_ino = sizeof(__u32);
	free = ext2fs_attr_free_space(last, &offs, start, &total_ino);

	/* Enough free space available in the inode for expansion */
	if (free >= new_extra_isize) {
		ext2fs_attr_shift_entries(entry, inode->i_extra_isize -
				new_extra_isize, (char *)inode +
				EXT2_GOOD_OLD_INODE_SIZE + new_extra_isize,
				(char *)start - sizeof(__u32), total_ino);
		inode->i_extra_isize = new_extra_isize;
		if (needed_size)
			*needed_size = 0;
		goto write_inode;
	}

	if (inode->i_file_acl) {
		error = ext2fs_read_ext_attr(fs, inode->i_file_acl, block_buf);
		if (error)
			 goto cleanup;

		header = BHDR(block_buf);
		if (header->h_magic != EXT2_EXT_ATTR_MAGIC) {
			error = EXT2_ET_EA_BAD_MAGIC;
			goto cleanup;
		}
		end = block_buf + fs->blocksize;
		last = entry = (struct ext2_ext_attr_entry *)(header+1);
		start = (char *) entry;
		offs = end - start;
		free = ext2fs_attr_free_space(last, &offs, start, &total_blk);
		if (free < new_extra_isize) {
			if (!tried_min_extra_isize && s_min_extra_isize) {
				tried_min_extra_isize++;
				new_extra_isize = s_min_extra_isize;
				goto retry;
			}
			if (ret)
				*ret = EXT2_EXPAND_EISIZE_NOSPC;
			error = EXT2_ET_EA_NO_SPACE;
			goto cleanup;
		}
	} else {
		if (ret && *ret == EXT2_EXPAND_EISIZE_UNSAFE) {
			*ret = EXT2_EXPAND_EISIZE_NEW_BLOCK;
			error = 0;
			goto cleanup;
		}
		free = fs->blocksize;
	}

	while (new_extra_isize > 0) {
		int offs, size, entry_size;
		struct ext2_ext_attr_entry *small_entry = NULL;
		struct ext2_attr_info i = {
			.value = NULL,
			.value_len = 0,
		};
		unsigned int total_size, shift_bytes, temp = ~0U, extra_isize=0;

		start = (char *) inode + EXT2_GOOD_OLD_INODE_SIZE +
					inode->i_extra_isize + sizeof(__u32);
		end = (char *) inode + EXT2_INODE_SIZE(fs->super);
		last = (struct ext2_ext_attr_entry *) start;

		/* Find the entry best suited to be pushed into EA block */
		entry = NULL;
		for (; !EXT2_EXT_IS_LAST_ENTRY(last);
			last = EXT2_EXT_ATTR_NEXT(last)) {
			total_size = EXT2_EXT_ATTR_SIZE(last->e_value_size) +
					EXT2_EXT_ATTR_LEN(last->e_name_len);
			if (total_size <= free && total_size < temp) {
				if (total_size < new_extra_isize) {
					small_entry = last;
				} else {
					entry = last;
					temp = total_size;
				}
			}
		}

		if (entry == NULL) {
			if (small_entry) {
				entry = small_entry;
			} else {
				if (!tried_min_extra_isize &&
				    s_min_extra_isize) {
					tried_min_extra_isize++;
					new_extra_isize = s_min_extra_isize;
					goto retry;
				}
				if (ret)
					*ret = EXT2_EXPAND_EISIZE_NOSPC;
				error = EXT2_ET_EA_NO_SPACE;
				goto cleanup;
			}
		}
		offs = entry->e_value_offs;
		size = entry->e_value_size;
		entry_size = EXT2_EXT_ATTR_LEN(entry->e_name_len);
		i.name_index = entry->e_name_index;
		error = ext2fs_get_mem(size, &buffer);
		if (error)
			goto cleanup;
		error = ext2fs_get_mem(entry->e_name_len + 1, &b_entry_name);
		if (error)
			goto cleanup;
		/* Save the entry name and the entry value */
		memcpy((char *)buffer, (char *) start + offs,
		       EXT2_EXT_ATTR_SIZE(size));
		memcpy((char *)b_entry_name, (char *)entry->e_name,
		       entry->e_name_len);
		b_entry_name[entry->e_name_len] = '\0';
		i.name = b_entry_name;

		error = ext2fs_attr_ibody_find(fs, inode, &i, &is);
		if (error)
			goto cleanup;

		error = ext2fs_attr_set_entry(fs, &i, &is.s);
		if (error)
			goto cleanup;

		entry = (struct ext2_ext_attr_entry *) start;
		if (entry_size + EXT2_EXT_ATTR_SIZE(size) >= new_extra_isize)
			shift_bytes = new_extra_isize;
		else
			shift_bytes = entry_size + EXT2_EXT_ATTR_SIZE(size);
		ext2fs_attr_shift_entries(entry, inode->i_extra_isize -
			shift_bytes, (char *)inode +
			EXT2_GOOD_OLD_INODE_SIZE + extra_isize + shift_bytes,
			(char *)start - sizeof(__u32), total_ino - entry_size);

		extra_isize += shift_bytes;
		new_extra_isize -= shift_bytes;
		if (needed_size)
			*needed_size = new_extra_isize;
		inode->i_extra_isize = extra_isize;

		i.name = b_entry_name;
		i.value = buffer;
		i.value_len = size;
		error = ext2fs_attr_block_find(fs, (struct ext2_inode *) inode,
					       &i, &bs);
		if (error)
			goto cleanup;

		/* Add entry which was removed from the inode into the block */
		error = ext2fs_attr_block_set(fs, (struct ext2_inode *) inode,
					      &i, &bs);
		if (error)
			goto cleanup;
	}

write_inode:
	error = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *) inode,
					EXT2_INODE_SIZE(fs->super));
cleanup:
	if (inode_buf)
		ext2fs_free_mem(&inode_buf);
	if (block_buf)
		ext2fs_free_mem(&block_buf);
	if (buffer)
		ext2fs_free_mem(&buffer);
	if (b_entry_name)
		ext2fs_free_mem(&b_entry_name);

	return error;
}
