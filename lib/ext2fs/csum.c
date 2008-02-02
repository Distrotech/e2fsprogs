/*
 * csum.c --- checksumming of ext3 structures
 *
 * Copyright (C) 2006 Cluster File Systems, Inc.
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Public
 * License.
 * %End-Header%
 */

#include "ext2_fs.h"
#include "ext2fs.h"
#include "crc16.h"
#include <assert.h>

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

__u16 ext2fs_group_desc_csum(struct ext2_super_block *sb, __u32 group,
			     struct ext2_group_desc *desc)
{
	crc16_t crc = 0;

	if (sb->s_feature_ro_compat & EXT4_FEATURE_RO_COMPAT_GDT_CSUM) {
		int offset = offsetof(struct ext2_group_desc, bg_checksum);

#ifdef WORDS_BIGENDIAN
		struct ext2_group_desc swabdesc = *desc;

		/* Have to swab back to little-endian to do the checksum */
		ext2fs_swap_group_desc(&swabdesc);
		desc = &swabdesc;

		group = ext2fs_swab32(group);
#endif
		crc = crc16(0xffff, sb->s_uuid, sizeof(sb->s_uuid));
		crc = crc16(crc, &group, sizeof(group));
		crc = crc16(crc, desc, offset);
		offset += sizeof(desc->bg_checksum); /* skip checksum */
		if (sb->s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT &&
		    sb->s_desc_size != 0 && offset < sb->s_desc_size)
			crc = crc16(crc, (char *)desc + offset,
				    sb->s_desc_size - offset);
	}

	return crc;
}

int ext2fs_group_desc_csum_verify(struct ext2_super_block *sb, __u32 group,
				  struct ext2_group_desc *desc)
{
	if (desc->bg_checksum != ext2fs_group_desc_csum(sb, group, desc))
		return 0;

	return 1;
}

static __u32 find_last_inode_ingrp(ext2fs_inode_bitmap bitmap,
				   __u32 inodes_per_grp, dgrp_t grp_no)
{
	ext2_ino_t i, start_ino, end_ino;

	start_ino = grp_no * inodes_per_grp + 1;
	end_ino = start_ino + inodes_per_grp - 1;

	for (i = end_ino; i >= start_ino; i--) {
		if (ext2fs_fast_test_inode_bitmap(bitmap, i))
			return i - start_ino + 1;
	}
	return inodes_per_grp;
}

/* update the bitmap flags, set the itable high watermark, and calculate
 * checksums for the group descriptors */
void ext2fs_set_gdt_csum(ext2_filsys fs)
{
	struct ext2_super_block *sb = fs->super;
	struct ext2_group_desc *bg = fs->group_desc;
	int blks, csum_flag, dirty = 0;
	int inodes_per_group = sb->s_inodes_per_group;
	dgrp_t i;

	csum_flag = EXT2_HAS_RO_COMPAT_FEATURE(fs->super,
					       EXT4_FEATURE_RO_COMPAT_GDT_CSUM);
	if (!EXT2_HAS_COMPAT_FEATURE(fs->super,
				     EXT2_FEATURE_COMPAT_LAZY_BG) && !csum_flag)
		return;

	for (i = 0; i < fs->group_desc_count; i++, bg++) {
		int old_csum = bg->bg_checksum;
		int old_unused = bg->bg_itable_unused;
		int old_flags = bg->bg_flags;

		/* Even if it wasn't zeroed, by the time this function is
		 * called by e2fsck we have already scanned and corrected
		 * the whole inode table so we may as well not overwrite it.
		 * This is just a hint to the kernel that it could do lazy
		 * zeroing of the inode table if mke2fs didn't do it, to help
		 * out if we need to do a full itable scan sometime later. */
		if (!(bg->bg_flags & (EXT2_BG_INODE_UNINIT |
				      EXT2_BG_INODE_ZEROED))) {
			bg->bg_flags |= EXT2_BG_INODE_ZEROED;
			dirty = 1;
		}

		if (bg->bg_free_inodes_count == inodes_per_group &&
		    i > 0 && (i < fs->group_desc_count - 1 || csum_flag)) {
			if (!(bg->bg_flags & EXT2_BG_INODE_UNINIT))
				bg->bg_flags |= EXT2_BG_INODE_UNINIT;

			if (csum_flag)
				bg->bg_itable_unused = inodes_per_group;

		} else if (csum_flag) {
			if (fs->inode_map)
				bg->bg_itable_unused = inodes_per_group -
					find_last_inode_ingrp(fs->inode_map,
							      inodes_per_group,
							      i);
			else if (bg->bg_flags & EXT2_BG_INODE_UNINIT)
				bg->bg_itable_unused = 0;

			bg->bg_flags &= ~EXT2_BG_INODE_UNINIT;
		}

		/* skip first and last groups, or groups with GDT backups
		 * because the resize inode has blocks allocated in them. */
		if (i == 0 || i == fs->group_desc_count - 1 ||
		    (ext2fs_bg_has_super(fs, i) && sb->s_reserved_gdt_blocks))
			goto checksum;

		blks = ext2fs_super_and_bgd_loc(fs, i, 0, 0, 0, 0);
		if (bg->bg_free_blocks_count == blks &&
		    bg->bg_flags & EXT2_BG_INODE_UNINIT &&
		    !(bg->bg_flags & EXT2_BG_BLOCK_UNINIT))
			bg->bg_flags |= EXT2_BG_BLOCK_UNINIT;
checksum:
		bg->bg_checksum = ext2fs_group_desc_csum(fs->super, i, bg);
		if (old_flags != bg->bg_flags)
			dirty = 1;
		if (old_unused != bg->bg_itable_unused)
			dirty = 1;
		if (old_csum != bg->bg_checksum)
			dirty = 1;
	}
	if (dirty)
		ext2fs_mark_super_dirty(fs);
}
