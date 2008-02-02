/*
 * block.h --- header for block iteration in block.c, extent.c
 *
 * Copyright (C) 1993, 1994, 1995, 1996 Theodore Ts'o.
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Public
 * License.
 * %End-Header%
 */

struct block_context {
	ext2_filsys	fs;
	int (*func)(ext2_filsys	fs,
		    blk_t	*blocknr,
		    e2_blkcnt_t	bcount,
		    blk_t	ref_blk,
		    int		ref_offset,
		    void	*priv_data);
	e2_blkcnt_t	bcount;
	int		bsize;
	int		flags;
	errcode_t	errcode;
	char	*ind_buf;
	char	*dind_buf;
	char	*tind_buf;
	void	*priv_data;
};

/* libext2fs nternal function, in extent.c */
extern int block_iterate_extents(void *eh_buf, unsigned bufsize,blk_t ref_block,
				 int ref_offset EXT2FS_ATTR((unused)),
				 struct block_context *ctx);
