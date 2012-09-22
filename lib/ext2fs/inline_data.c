/*
 * inline_data.c --- data in inode
 *
 * Copyright (C) 2012 Zheng Liu <wenqing.lz@taobao.com>
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU library
 * General Public License, version 2.
 * %End-Header%
 */

#include "config.h"
#include <stdio.h>
#include <time.h>

#include "ext2_fs.h"
#include "ext2_ext_attr.h"

#include "ext2fs.h"
#include "ext2fsP.h"

#define EXT4_INLINE_DATA_DOTDOT_SIZE	(4)

static int ext2fs_iget_extra_inode(ext2_filsys fs, struct ext2_inode_large *inode,
				    struct inline_data *data);
static void *ext2fs_get_inline_xattr_pos(struct ext2_inode_large *inode,
					 struct inline_data *data);

static int ext2fs_iget_extra_inode(ext2_filsys fs, struct ext2_inode_large *inode,
				    struct inline_data *data)
{
	struct ext2_ext_attr_ibody_header *header;
	struct ext2_ext_attr_search s = {
		.not_found = -1,
	};
	struct ext2_ext_attr_info i = {
		.name_index = EXT4_EXT_ATTR_INDEX_SYSTEM,
		.name = EXT4_EXT_ATTR_SYSTEM_DATA,
	};

	data->inline_off = 0;
	if (inode->i_extra_isize > (EXT2_INODE_SIZE(fs->super) -
				   EXT2_GOOD_OLD_INODE_SIZE))
		return EXT2_ET_BAD_EXTRA_SIZE;

	(void)ext2fs_ibody_find_ext_attr(fs, inode, &i, &s);

	if (!s.not_found) {
		data->inline_off = (__u16)((void *)s.here - (void *)inode);
		data->inline_size = EXT4_MIN_INLINE_DATA_SIZE +
				    s.here->e_value_size;
		return 0;
	}

	return EXT2_ET_BAD_EXT_ATTR_MAGIC;
}

static void *ext2fs_get_inline_xattr_pos(struct ext2_inode_large *inode,
					 struct inline_data *data)
{
	struct ext2_ext_attr_entry *entry;
	struct ext2_ext_attr_ibody_header *header;

	header = IHDR(inode);
	entry = (struct ext2_ext_attr_entry *)
			((void *)inode + data->inline_off);

	return (void *)IFIRST(header) + entry->e_value_offs;
}

int ext2fs_inode_has_inline_data(ext2_filsys fs, ext2_ino_t ino)
{
	struct ext2_inode inode;
	errcode_t retval;

	retval = ext2fs_read_inode(fs, ino, &inode);
	if (retval)
		return 0;

	return (inode.i_flags & EXT4_INLINE_DATA_FL);
}

int ext2fs_inline_data_iterate(ext2_filsys fs,
			       ext2_ino_t ino,
			       int flags,
			       char *block_buf,
			       int (*func)(ext2_filsys fs,
					   char *buf,
					   unsigned int buf_len,
					   e2_blkcnt_t blockcnt,
					   struct ext2_inode_large *inode,
					   void *priv_data),
			       void *priv_data)
{
	struct dir_context *ctx;
	struct ext2_inode_large *inode;
	struct ext2_dir_entry dirent;
	struct inline_data data;
	errcode_t retval = 0;
	e2_blkcnt_t blockcnt = 0;
	void *inline_start;
	int inline_size;

	ctx = (struct dir_context *)priv_data;

	retval = ext2fs_get_mem(EXT2_INODE_SIZE(fs->super), &inode);
	if (retval)
		return retval;

	retval = ext2fs_read_inode_full(fs, ino, (void *)inode,
					EXT2_INODE_SIZE(fs->super));
	if (retval)
		goto out;

	if (inode->i_size == 0)
		goto out;

	/* we first check '.' and '..' dir */
	dirent.inode = ino;
	dirent.name_len = 1;
	ext2fs_set_rec_len(fs, EXT2_DIR_REC_LEN(2), &dirent);
	dirent.name[0] = '.';
	dirent.name[1] = '\0';
	retval |= (*func)(fs, (void *)&dirent, dirent.rec_len, blockcnt++,
			 inode, priv_data);
	if (retval & BLOCK_ABORT)
		goto out;

	dirent.inode = (__u32)*inode->i_block;
	dirent.name_len = 2;
	ext2fs_set_rec_len(fs, EXT2_DIR_REC_LEN(3), &dirent);
	dirent.name[0] = '.';
	dirent.name[1] = '.';
	dirent.name[2] = '\0';
	retval |= (*func)(fs, (void *)&dirent, dirent.rec_len, blockcnt++,
			 inode, priv_data);
	if (retval & BLOCK_ABORT)
		goto out;

	inline_start = (void *)inode->i_block + EXT4_INLINE_DATA_DOTDOT_SIZE;
	inline_size = EXT4_MIN_INLINE_DATA_SIZE - EXT4_INLINE_DATA_DOTDOT_SIZE;
	retval |= (*func)(fs, inline_start, inline_size, blockcnt++,
			 inode, priv_data);
	if (retval & BLOCK_ABORT)
		goto out;

	retval = ext2fs_iget_extra_inode(fs, inode, &data);
	if (retval)
		goto out;
	if (data.inline_size > EXT4_MIN_INLINE_DATA_SIZE) {
		inline_start = ext2fs_get_inline_xattr_pos(inode, &data);
		inline_size = data.inline_size - EXT4_MIN_INLINE_DATA_SIZE;
		retval |= (*func)(fs, inline_start, inline_size, blockcnt++,
			 inode, priv_data);
		if (retval & BLOCK_ABORT)
			goto out;
	}

out:
	retval |= BLOCK_ERROR;
	ext2fs_free_mem(&inode);
	return retval & BLOCK_ERROR ? ctx->errcode : 0;
}
