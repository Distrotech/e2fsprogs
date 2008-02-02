/*
 * Helper functions for multiple mount protection(MMP).
 *
 * Copyright (C) 2006, 2007 by Kalpak Shah <kalpak@clusterfs.com>
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Public
 * License.
 * %End-Header%
 */

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/time.h>

#include "ext2fs/ext2_fs.h"
#include "ext2fs/ext2fs.h"

errcode_t ext2fs_read_mmp(ext2_filsys fs, blk_t mmp_blk, char *buf)
{
	struct mmp_struct *mmp_s;
	errcode_t retval;

	if ((mmp_blk < fs->super->s_first_data_block) ||
	    (mmp_blk >= fs->super->s_blocks_count))
		return EXT2_ET_MMP_BAD_BLOCK;

	/*
	 * Make sure that we read direct from disk by reading only
	 * sizeof(stuct mmp_struct) bytes.
	 */
	retval = io_channel_read_blk(fs->io, mmp_blk,
				     -(int)sizeof(struct mmp_struct), buf);
	if (retval)
		return retval;

	mmp_s = (struct mmp_struct *) buf;

#ifdef EXT2FS_ENABLE_SWAPFS
	if (fs->flags & EXT2_FLAG_SWAP_BYTES)
		ext2fs_swap_mmp(mmp_s);
#endif

	if (mmp_s->mmp_magic != EXT2_MMP_MAGIC)
		return EXT2_ET_MMP_MAGIC_INVALID;

	return 0;
}

errcode_t ext2fs_write_mmp(ext2_filsys fs, blk_t mmp_blk, char *buf)
{
	struct mmp_struct *mmp_s = (struct mmp_struct *) buf;
	struct timeval tv;
	int retval;

	gethostname(mmp_s->mmp_nodename, sizeof(mmp_s->mmp_nodename));
	gettimeofday(&tv, 0);
	mmp_s->mmp_time = tv.tv_sec;

#ifdef EXT2FS_ENABLE_SWAPFS
	if (fs->super->s_magic == ext2fs_swab16(EXT2_SUPER_MAGIC))
		ext2fs_swap_mmp(mmp_s);
#endif

	retval = io_channel_write_blk(fs->io, mmp_blk,
				      -(int)sizeof(struct mmp_struct), buf);

#ifdef EXT2FS_ENABLE_SWAPFS
	if (fs->super->s_magic == ext2fs_swab16(EXT2_SUPER_MAGIC))
		ext2fs_swap_mmp(mmp_s);
#endif

	/*
	 * Make sure the block gets to disk quickly.
	 */
	io_channel_flush(fs->io);
	return retval;
}

long int ext2fs_mmp_new_seq()
{
	long int new_seq;

	do {
		new_seq = random();
	} while (new_seq > EXT2_MMP_SEQ_MAX);

	return new_seq;
}

errcode_t ext2fs_enable_mmp(ext2_filsys fs)
{
	struct ext2_super_block *sb = fs->super;
	struct mmp_struct *mmp_s = NULL;
	blk_t mmp_block;
	char *buf;
	int error;

	error = ext2fs_read_bitmaps(fs);
	if (error)
		goto out;

	error = ext2fs_new_block(fs, 0, 0, &mmp_block);
	if (error)
		goto out;

	ext2fs_block_alloc_stats(fs, mmp_block, +1);
	sb->s_mmp_block = mmp_block;

	error = ext2fs_get_mem(fs->blocksize, &buf);
	if (error)
		goto out;

	mmp_s = (struct mmp_struct *) buf;
	memset(mmp_s, 0, sizeof(struct mmp_struct));

	mmp_s->mmp_magic = EXT2_MMP_MAGIC;
	mmp_s->mmp_seq = EXT2_MMP_SEQ_CLEAN;
	mmp_s->mmp_time = 0;
	mmp_s->mmp_nodename[0] = '\0';
	mmp_s->mmp_bdevname[0] = '\0';
	mmp_s->mmp_check_interval = EXT2_MMP_MIN_CHECK_INTERVAL;

	error = ext2fs_write_mmp(fs, mmp_block, buf);
	if (error) {
		if (buf)
			ext2fs_free_mem(&buf);
		goto out;
	}

	if (buf)
		ext2fs_free_mem(&buf);

	sb->s_mmp_update_interval = EXT2_MMP_UPDATE_INTERVAL;

out:
	return error;
}
