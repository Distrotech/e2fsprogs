/*
 * ind_block.c --- indirect block I/O routines
 * 
 * Copyright (C) 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 
 * 	2001, 2002, 2003, 2004, 2005 by  Theodore Ts'o.
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Public
 * License.
 * %End-Header%
 */

#include <stdio.h>
#include <string.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ext2_fs.h"
#include "ext2fs.h"

errcode_t ext2fs_read_ind_block(ext2_filsys fs, blk_t blk, void *buf)
{
	errcode_t	retval;
	int	limit = fs->blocksize >> 2;
	blk_t	*block_nr = (blk_t *)buf;
	int	i;

	if ((fs->flags & EXT2_FLAG_IMAGE_FILE) &&
	    (fs->io != fs->image_io))
		memset(buf, 0, fs->blocksize);
	else {
		retval = io_channel_read_blk(fs->io, blk, 1, buf);
		if (retval)
			return retval;
	}
#ifdef EXT2FS_ENABLE_SWAPFS
	if (fs->flags & (EXT2_FLAG_SWAP_BYTES | EXT2_FLAG_SWAP_BYTES_READ)) {
		for (i = 0; i < limit; i++, block_nr++)
			*block_nr = ext2fs_swab32(*block_nr);
	}
#endif
	return 0;
}

errcode_t ext2fs_write_ind_block(ext2_filsys fs, blk_t blk, void *buf)
{
	blk_t		*block_nr;
	int		i;
	int		limit = fs->blocksize >> 2;

	if (fs->flags & EXT2_FLAG_IMAGE_FILE)
		return 0;

#ifdef EXT2FS_ENABLE_SWAPFS
	if (fs->flags & (EXT2_FLAG_SWAP_BYTES | EXT2_FLAG_SWAP_BYTES_WRITE)) {
		block_nr = (blk_t *) buf;
		for (i = 0; i < limit; i++, block_nr++)
			*block_nr = ext2fs_swab32(*block_nr);
	}
#endif
	return io_channel_write_blk(fs->io, blk, 1, buf);
}


errcode_t ext2fs_read_ext_block(ext2_filsys fs, blk_t blk, void *buf)
{
	errcode_t	retval;

	if ((fs->flags & EXT2_FLAG_IMAGE_FILE) &&
	    (fs->io != fs->image_io))
		memset(buf, 0, fs->blocksize);
	else {
		retval = io_channel_read_blk(fs->io, blk, 1, buf);
		if (retval)
			return retval;
	}
#ifdef EXT2FS_ENABLE_SWAPFS
	if (fs->flags & (EXT2_FLAG_SWAP_BYTES | EXT2_FLAG_SWAP_BYTES_READ)) {
		struct ext3_extent_header *eh = buf;
		int i, limit;

		ext2fs_swap_extent_header(eh);

		if (eh->eh_depth == 0) {
			struct ext3_extent *ex = EXT_FIRST_EXTENT(eh);

			limit = (fs->blocksize - sizeof(*eh)) / sizeof(*ex);
			if (eh->eh_entries < limit)
				limit = eh->eh_entries;

			for (i = 0; i < limit; i++, ex++)
				ext2fs_swap_extent(ex);
		} else {
			struct ext3_extent_idx *ix = EXT_FIRST_INDEX(eh);

			limit = (fs->blocksize - sizeof(*eh)) / sizeof(*ix);
			if (eh->eh_entries < limit)
				limit = eh->eh_entries;

			for (i = 0; i < limit; i++, ix++)
				ext2fs_swap_extent_index(ix);
		}
	}
#endif
	return 0;
}

errcode_t ext2fs_write_ext_block(ext2_filsys fs, blk_t blk, void *buf)
{
	if (fs->flags & EXT2_FLAG_IMAGE_FILE)
		return 0;

#ifdef EXT2FS_ENABLE_SWAPFS
	if (fs->flags & (EXT2_FLAG_SWAP_BYTES | EXT2_FLAG_SWAP_BYTES_WRITE)) {
		struct ext3_extent_header *eh = buf;
		int i, limit;

		if (eh->eh_depth == 0) {
			struct ext3_extent *ex = EXT_FIRST_EXTENT(eh);

			limit = (fs->blocksize - sizeof(*eh)) / sizeof(*ex);
			if (eh->eh_entries < limit)
				limit = eh->eh_entries;

			for (i = 0; i < limit; i++, ex++)
				ext2fs_swap_extent(ex);
		} else {
			struct ext3_extent_idx *ix = EXT_FIRST_INDEX(eh);

			limit = (fs->blocksize - sizeof(*eh)) / sizeof(*ix);
			if (eh->eh_entries < limit)
				limit = eh->eh_entries;

			for (i = 0; i < limit; i++, ix++)
				ext2fs_swap_extent_index(ix);
		}

		ext2fs_swap_extent_header(eh);
	}
#endif
	return io_channel_write_blk(fs->io, blk, 1, buf);
}

