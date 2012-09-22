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

#include "ext2fs.h"
#include "ext2fsP.h"

int ext2fs_inode_has_inline_data(ext2_filsys fs, ext2_ino_t ino)
{
	struct ext2_inode inode;
	errcode_t retval;

	retval = ext2fs_read_inode(fs, ino, &inode);
	if (retval)
		return 0;

	return (inode.i_flags & EXT4_INLINE_DATA_FL);
}
