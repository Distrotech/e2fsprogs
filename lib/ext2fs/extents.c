/*
 * extent.c --- iterate over all blocks in an extent-mapped inode
 *
 * Copyright (C) 2005 Alex Tomas <alex@clusterfs.com>
 * Copyright (C) 2006 Andreas Dilger <adilger@clusterfs.com>
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
#include "block.h"

#ifdef EXT_DEBUG
void ext_show_header(struct ext3_extent_header *eh)
{
	printf("header: magic=%x entries=%u max=%u depth=%u generation=%u\n",
	       eh->eh_magic, eh->eh_entries, eh->eh_max, eh->eh_depth,
	       eh->eh_generation);
}

void ext_show_index(struct ext3_extent_idx *ix)
{
	printf("index: block=%u leaf=%u leaf_hi=%u unused=%u\n",
	       ix->ei_block, ix->ei_leaf, ix->ei_leaf_hi, ix->ei_unused);
}

void ext_show_extent(struct ext3_extent *ex)
{
	printf("extent: block=%u-%u len=%u start=%u start_hi=%u\n",
	       ex->ee_block, ex->ee_block + ex->ee_len - 1,
	       ex->ee_len, ex->ee_start, ex->ee_start_hi);
}

#define ext_printf(fmt, args...) printf(fmt, ## args)
#else
#define ext_show_header(eh) do { } while (0)
#define ext_show_index(ix) do { } while (0)
#define ext_show_extent(ex) do { } while (0)
#define ext_printf(fmt, args...) do { } while (0)
#endif

errcode_t ext2fs_extent_header_verify(struct ext3_extent_header *eh, int size)
{
	int eh_max, entry_size;

	ext_show_header(eh);
	if (eh->eh_magic != EXT3_EXT_MAGIC)
		return EXT2_ET_EXTENT_HEADER_BAD;
	if (eh->eh_entries > eh->eh_max)
		return EXT2_ET_EXTENT_HEADER_BAD;
	if (eh->eh_depth == 0)
		entry_size = sizeof(struct ext3_extent);
	else
		entry_size = sizeof(struct ext3_extent_idx);

	eh_max = (size - sizeof(*eh)) / entry_size;
	/* Allow two extent-sized items at the end of the block, for
	 * ext4_extent_tail with checksum in the future. */
	if (eh->eh_max > eh_max || eh->eh_max < eh_max - 2)
		return EXT2_ET_EXTENT_HEADER_BAD;

	return 0;
}

/* Verify that a single extent @ex is valid.  If @ex_prev is passed in,
 * then this was the previous logical extent in this block and we can
 * do additional sanity checking (though in case of error we don't know
 * which of the two extents is bad).  Similarly, if @ix is passed in
 * we can check that this extent is logically part of the index that
 * refers to it (though again we can't know which of the two is bad). */
errcode_t ext2fs_extent_verify(ext2_filsys fs, struct ext3_extent *ex,
			       struct ext3_extent *ex_prev,
			       struct ext3_extent_idx *ix, int ix_len)
{
	ext_show_extent(ex);
	/* FIXME: 48-bit support */
	if (ex->ee_start > fs->super->s_blocks_count)
		return EXT2_ET_EXTENT_LEAF_BAD;

	if (ex->ee_len == 0)
		return EXT2_ET_EXTENT_LEAF_BAD;

	if (ex->ee_len >= fs->super->s_blocks_per_group)
		return EXT2_ET_EXTENT_LEAF_BAD;

	if (ex_prev) {
		/* We can't have a zero logical block except for first index */
		if (ex->ee_block == 0)
			return EXT2_ET_EXTENT_LEAF_BAD;

		/* FIXME: 48-bit support */
		/* extents must be in logical offset order */
		if (ex->ee_block < ex_prev->ee_block + ex_prev->ee_len)
			return EXT2_ET_EXTENT_LEAF_BAD;

		/* extents must not overlap physical blocks */
		if ((ex->ee_start < ex_prev->ee_start + ex_prev->ee_len) &&
		    (ex->ee_start + ex->ee_len > ex_prev->ee_start))
			return EXT2_ET_EXTENT_LEAF_BAD;
	}

	if (ix) {
		/* FIXME: 48-bit support */
		if (ex->ee_block < ix->ei_block)
			return EXT2_ET_EXTENT_LEAF_BAD;

		if (ix_len && ex->ee_block + ex->ee_len > ix->ei_block + ix_len)
			return EXT2_ET_EXTENT_LEAF_BAD;
	}

	return 0;
}

errcode_t ext2fs_extent_index_verify(ext2_filsys fs, struct ext3_extent_idx *ix,
				     struct ext3_extent_idx *ix_prev)
{
	ext_show_index(ix);
	/* FIXME: 48-bit support */
	if (ix->ei_leaf > fs->super->s_blocks_count)
		return EXT2_ET_EXTENT_INDEX_BAD;

	if (ix_prev == NULL)
		return 0;

	/* We can't have a zero logical block except for first index */
	if (ix->ei_block == 0)
		return EXT2_ET_EXTENT_INDEX_BAD;

	if (ix->ei_block <= ix_prev->ei_block)
		return EXT2_ET_EXTENT_INDEX_BAD;

	return 0;
}

errcode_t ext2fs_extent_remove(struct ext3_extent_header *eh,
			       struct ext3_extent *ex)
{
	int offs = ex - EXT_FIRST_EXTENT(eh);

	if (offs < 0 || offs > eh->eh_entries)
		return EXT2_ET_EXTENT_LEAF_BAD;

	ext_printf("remove extent: offset %u\n", offs);

	memmove(ex, ex + 1, (eh->eh_entries - offs - 1) * sizeof(*ex));
	--eh->eh_entries;

	return 0;
}

static errcode_t ext2fs_extent_split_internal(struct ext3_extent_header *eh,
					      struct ext3_extent *ex, int offs)
{
	int entry = ex - EXT_FIRST_EXTENT(eh);
	struct ext3_extent *ex_new = ex + 1;

	ext_printf("split: ee_len: %u ee_block: %u ee_start: %u offset: %u\n",
		   ex->ee_len, ex->ee_block, ex->ee_start, offs);
	memmove(ex_new, ex, (eh->eh_entries - entry) * sizeof(*ex));
	++eh->eh_entries;

	ex->ee_len = offs;
	/* FIXME: 48-bit support */
	ex_new->ee_len -= offs;
	ex_new->ee_block += offs;
	ex_new->ee_start += offs;

	return 0;
}

errcode_t ext2fs_extent_split(ext2_filsys fs,
			      struct ext3_extent_header **eh_orig,
			      struct ext3_extent **ex_orig, int offs, int *flag)
{
	struct ext3_extent_header *eh_parent = *eh_orig;
	int retval, entry = *ex_orig - EXT_FIRST_EXTENT(eh_parent);
	blk_t new_block;
	char *buf;
	struct ext3_extent_idx *ei = EXT_FIRST_INDEX(eh_parent);

	if (entry < 0 || entry > (*eh_orig)->eh_entries)
		return EXT2_ET_EXTENT_LEAF_BAD;

	if (offs > (*ex_orig)->ee_len)
		return EXT2_ET_EXTENT_LEAF_BAD;

	if (eh_parent->eh_entries >= eh_parent->eh_max) {
		ext_printf("split: eh_entries: %u eh_max: %u\n",
			   eh_parent->eh_entries, eh_parent->eh_max);
		if (eh_parent->eh_max == 4) {
			struct ext3_extent_header *eh_child;
			struct ext3_extent *ex_child;

			retval = ext2fs_get_mem(fs->blocksize, &buf);

			if (retval)
				return EXT2_ET_EXTENT_NO_SPACE;

			memset(buf, 0, fs->blocksize);
			memcpy(buf, eh_parent, sizeof(*eh_parent) +
			       eh_parent->eh_entries * sizeof(*ex_child));
			eh_child = (struct ext3_extent_header *)buf;

			eh_child->eh_max = (fs->blocksize -
					    sizeof(struct ext3_extent_header)) /
					   sizeof(struct ext3_extent);
			retval = ext2fs_new_block(fs, (*ex_orig)->ee_block, 0,
						  &new_block);
			if (retval)
				return EXT2_ET_EXTENT_NO_SPACE;

			retval = io_channel_write_blk(fs->io, new_block, 1,buf);
			if (retval)
				return EXT2_ET_EXTENT_NO_SPACE;

			eh_parent->eh_entries = 1;
			eh_parent->eh_depth = 1;

			ex_child = EXT_FIRST_EXTENT(eh_child);
			ei->ei_block = ex_child->ee_block;
			/* FIXME: 48-bit support*/
			ei->ei_leaf = new_block;

			*eh_orig = eh_child;
			*ex_orig = EXT_FIRST_EXTENT(eh_child) + entry;

			*flag = BLOCK_CHANGED;
		} else {
			return EXT2_ET_EXTENT_NO_SPACE;
		}
	}

	return ext2fs_extent_split_internal(*eh_orig, *ex_orig, offs);
}

errcode_t ext2fs_extent_index_remove(struct ext3_extent_header *eh,
				     struct ext3_extent_idx *ix)
{
	struct ext3_extent_idx *first = EXT_FIRST_INDEX(eh);
	int offs = ix - first;

	ext_printf("remove index: offset %u\n", offs);

	memmove(ix, ix + 1, (eh->eh_entries - offs - 1) * sizeof(*ix));
	--eh->eh_entries;

	return 0;
}

/* Internal function for ext2fs_block_iterate2() to recursively walk the
 * extent tree, with a callback function for each block.  We also call the
 * callback function on index blocks unless BLOCK_FLAG_DATA_ONLY is given.
 * We traverse the tree in-order (internal nodes before their children)
 * unless BLOCK_FLAG_DEPTH_FIRST is given.
 *
 * See also block_bmap_extents(). */
int block_iterate_extents(void *eh_buf, unsigned bufsize, blk_t ref_block,
			  int ref_offset EXT2FS_ATTR((unused)),
			  struct block_context *ctx)
{
	struct ext3_extent_header *orig_eh, *eh;
	struct ext3_extent *ex, *ex_prev = NULL;
	int ret = 0;
	int item, offs, flags, split_flag = 0;
	blk_t block_address;

	orig_eh = eh = eh_buf;

	if (ext2fs_extent_header_verify(eh, bufsize))
		return BLOCK_ERROR;

	if (eh->eh_depth == 0) {
		ex = EXT_FIRST_EXTENT(eh);
		for (item = 0; item < eh->eh_entries; item++, ex++) {
			ext_show_extent(ex);
			for (offs = 0; offs < ex->ee_len; offs++) {
				block_address = ex->ee_start + offs;
				flags = (*ctx->func)(ctx->fs, &block_address,
						     (ex->ee_block + offs),
						     ref_block, item,
						     ctx->priv_data);
				if (flags & (BLOCK_ABORT | BLOCK_ERROR)) {
					ret |= flags &(BLOCK_ABORT|BLOCK_ERROR);
					return ret;
				}
				if (!(flags & BLOCK_CHANGED))
					continue;

				ext_printf("extent leaf changed: "
					   "block was %u+%u = %u, now %u\n",
					   ex->ee_start, offs,
					   ex->ee_start + offs, block_address);

				/* FIXME: 48-bit support */
				if (ex_prev &&
				    block_address ==
				    ex_prev->ee_start + ex_prev->ee_len &&
				    ex->ee_block + offs ==
				    ex_prev->ee_block + ex_prev->ee_len) {
					/* can merge block with prev extent */
					ex_prev->ee_len++;
					ex->ee_len--;
					ret |= BLOCK_CHANGED;

					if (ex->ee_len == 0) {
						/* no blocks left in this one */
						ext2fs_extent_remove(eh, ex);
						item--; ex--;
						break;
					} else {
						/* FIXME: 48-bit support */
						ex->ee_start++;
						ex->ee_block++;
						offs--;
					}

				} else if (offs > 0 && /* implies ee_len > 1 */
					   (ctx->errcode =
					    ext2fs_extent_split(ctx->fs, &eh,
								&ex, offs,
								&split_flag)
					    /* advance ex past newly split item,
					     * comparison is bogus to make sure
					     * increment doesn't change logic */
					    || (offs > 0 && ex++ == NULL))) {
					/* split before new block failed */
					ret |= BLOCK_ABORT | BLOCK_ERROR;
					return ret;

				} else if (ex->ee_len > 1 &&
					   (ctx->errcode =
					    ext2fs_extent_split(ctx->fs, &eh,
								&ex, 1,
								&split_flag))) {
					/* split after new block failed */
					ret |= BLOCK_ABORT | BLOCK_ERROR;
					return ret;

				} else {
					if (ex->ee_len != 1) {
						/* this is an internal error */
						ctx->errcode =
						       EXT2_ET_EXTENT_INDEX_BAD;
						ret |= BLOCK_ABORT |BLOCK_ERROR;
						return ret;
					}
					/* FIXME: 48-bit support */
					ex->ee_start = block_address;
					ret |= BLOCK_CHANGED;
				}
			}
			ex_prev = ex;
		}
		/* Multi level split at depth == 0.
		 * ex has been changed to point to  newly allocated block
		 * buffer. And after returning  in this scenario, only inode is
		 * updated with changed i_block. Hence explicitly write to the
		 * block is required. */
		if (split_flag == BLOCK_CHANGED) {
			struct ext3_extent_idx *ix = EXT_FIRST_INDEX(orig_eh);
			ctx->errcode = ext2fs_write_ext_block(ctx->fs,
							      ix->ei_leaf, eh);
		}
	} else {
		char *block_buf;
		struct ext3_extent_idx *ix;

		ret = ext2fs_get_mem(ctx->fs->blocksize, &block_buf);
		if (ret)
			return ret;

		ext_show_header(eh);
		ix = EXT_FIRST_INDEX(eh);
		for (item = 0; item < eh->eh_entries; item++, ix++) {
			ext_show_index(ix);
			/* index is processed first in e2fsck case */
			if (!(ctx->flags & BLOCK_FLAG_DEPTH_TRAVERSE) &&
			    !(ctx->flags & BLOCK_FLAG_DATA_ONLY)) {
				block_address = ix->ei_leaf;
				flags = (*ctx->func)(ctx->fs, &block_address,
						     BLOCK_COUNT_IND, ref_block,
						     item, ctx->priv_data);
				if (flags & (BLOCK_ABORT | BLOCK_ERROR)) {
					ret |= flags &(BLOCK_ABORT|BLOCK_ERROR);
					goto free_buf;
				}
				if (flags & BLOCK_CHANGED) {
					ret |= BLOCK_CHANGED;
					/* index has no more block, remove it */
					/* FIXME: 48-bit support */
					ix->ei_leaf = block_address;
					if (ix->ei_leaf == 0 &&
					    ix->ei_leaf_hi == 0) {
						if(ext2fs_extent_index_remove(eh, ix)) {
							ret |= BLOCK_ABORT |BLOCK_ERROR;
							goto free_buf;
						} else {
							--item;	--ix;
							continue;
						}
					}
					/* remapped? */
				}
			}
			ctx->errcode = ext2fs_read_ext_block(ctx->fs,
							     ix->ei_leaf,
							     block_buf);
			if (ctx->errcode) {
				ret |= BLOCK_ERROR;
				goto free_buf;
			}
			flags = block_iterate_extents(block_buf,
						      ctx->fs->blocksize,
						      ix->ei_leaf, item, ctx);
			if (flags & BLOCK_CHANGED) {
				struct ext3_extent_header *nh;
				ctx->errcode =
					ext2fs_write_ext_block(ctx->fs,
							       ix->ei_leaf,
							       block_buf);

				nh = (struct ext3_extent_header *)block_buf;
				if (nh->eh_entries == 0)
					ix->ei_leaf = ix->ei_leaf_hi = 0;
			}
			if (flags & (BLOCK_ABORT | BLOCK_ERROR)) {
				ret |= flags & (BLOCK_ABORT | BLOCK_ERROR);
				goto free_buf;
			}
			if ((ctx->flags & BLOCK_FLAG_DEPTH_TRAVERSE) &&
			    !(ctx->flags & BLOCK_FLAG_DATA_ONLY)) {
				flags = (*ctx->func)(ctx->fs, &block_address,
						     BLOCK_COUNT_IND, ref_block,
						     item, ctx->priv_data);
				if (flags & (BLOCK_ABORT | BLOCK_ERROR)) {
					ret |= flags &(BLOCK_ABORT|BLOCK_ERROR);
					goto free_buf;
				}
				if (flags & BLOCK_CHANGED)
					/* FIXME: 48-bit support */
					ix->ei_leaf = block_address;
			}

			if (flags & BLOCK_CHANGED) {
				/* index has no more block, remove it */
				if (ix->ei_leaf == 0 && ix->ei_leaf_hi == 0 &&
				    ext2fs_extent_index_remove(eh, ix)) {
					ret |= BLOCK_ABORT |BLOCK_ERROR;
					goto free_buf;
				}

				ret |= BLOCK_CHANGED;
				if (ref_block == 0) {
					--item; --ix;
					continue;
				}
				/* remapped? */
			}
		}

	free_buf:
		ext2fs_free_mem(&block_buf);
	}
	return ret;
}
