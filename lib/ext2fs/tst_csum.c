/*
 * This testing program verifies checksumming operations
 *
 * Copyright (C) 2006, 2007 by Andreas Dilger <adilger@clusterfs.com>
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Public
 * License.
 * %End-Header%
 */

#include "ext2fs/ext2_fs.h"
#include "ext2fs/ext2fs.h"
#include "ext2fs/crc16.h"
#include "uuid/uuid.h"

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

void print_csum(const char *msg, struct ext2_super_block *sb,
		__u32 group, struct ext2_group_desc *desc)
{
	__u16 crc1, crc2, crc3;
	__u32 swabgroup;
	char uuid[40];

#ifdef WORDS_BIGENDIAN
	struct ext2_group_desc swabdesc = *desc;

	/* Have to swab back to little-endian to do the checksum */
	ext2fs_swap_group_desc(&swabdesc);
	desc = &swabdesc;

	swabgroup = ext2fs_swab32(group);
#else
	swabgroup = group;
#endif

	crc1 = crc16(0xffff, sb->s_uuid, sizeof(sb->s_uuid));
	crc2 = crc16(crc1, &swabgroup, sizeof(swabgroup));
	crc3 = crc16(crc2, desc, offsetof(struct ext2_group_desc, bg_checksum));
	uuid_unparse(sb->s_uuid, uuid);
	printf("%s: UUID %s=%04x, grp %u=%04x: %04x=%04x\n",
	       msg, uuid, crc1, group, crc2, crc3,
	       ext2fs_group_desc_csum(sb, group,desc));
}

int main(int argc, char **argv)
{
	struct ext2_group_desc desc = { .bg_block_bitmap = 124,
					.bg_inode_bitmap = 125,
					.bg_inode_table = 126,
					.bg_free_blocks_count = 31119,
					.bg_free_inodes_count = 15701,
					.bg_used_dirs_count = 2,
					.bg_flags = 0,
					};
	struct ext2_super_block sb = {  .s_feature_ro_compat =
					EXT4_FEATURE_RO_COMPAT_GDT_CSUM,
					.s_uuid = { 0x4f, 0x25, 0xe8, 0xcf,
						    0xe7, 0x97, 0x48, 0x23,
						    0xbe, 0xfa, 0xa7, 0x88,
						    0x4b, 0xae, 0xec, 0xdb } };
	__u16 csum1, csum2, csum_known = 0xd3a4;
	char data[8] = { 0x10, 0x20, 0x30, 0x40, 0xf1, 0xb2, 0xc3, 0xd4 };
	__u16 data_crc[8] =   { 0xcc01, 0x180c, 0x1118, 0xfa10,
				0x483a, 0x6648, 0x6726, 0x85e6 };
	__u16 data_crc0[8] =  { 0x8cbe, 0xa80d, 0xd169, 0xde10,
				0x481e, 0x7d48, 0x673d, 0x8ea6 };
	int i;

	for (i = 0; i < sizeof(data); i++) {
		csum1 = crc16(0, data, i + 1);
		printf("crc16(0): data[%d]: %04x=%04x\n", i, csum1,data_crc[i]);
		if (csum1 != data_crc[i]) {
			printf("error: crc16(0) for data[%d] should be %04x\n",
			       i, data_crc[i]);
			exit(1);
		}
	}

	for (i = 0; i < sizeof(data); i++) {
		csum1 = crc16(~0, data, i + 1);
		printf("crc16(~0): data[%d]: %04x=%04x\n",i,csum1,data_crc0[i]);
		if (csum1 != data_crc0[i]) {
			printf("error: crc16(~0) for data[%d] should be %04x\n",
			       i, data_crc0[i]);
			exit(1);
		}
	}

	csum1 = ext2fs_group_desc_csum(&sb, 0, &desc);
	print_csum("csum0000", &sb, 0, &desc);

	if (csum1 != csum_known) {
		printf("checksum for group 0 should be %04x\n", csum_known);
		exit(1);
	}
	csum2 = ext2fs_group_desc_csum(&sb, 1, &desc);
	print_csum("csum0001", &sb, 1, &desc);
	if (csum1 == csum2) {
		printf("checksums for different groups shouldn't match\n");
		exit(1);
	}
	csum2 = ext2fs_group_desc_csum(&sb, 0xffff, &desc);
	print_csum("csumffff", &sb, 0xffff, &desc);
	if (csum1 == csum2) {
		printf("checksums for different groups shouldn't match\n");
		exit(1);
	}
	desc.bg_checksum = csum1;
	csum2 = ext2fs_group_desc_csum(&sb, 0, &desc);
	print_csum("csum_set", &sb, 0, &desc);
	if (csum1 != csum2) {
		printf("checksums should not depend on checksum field\n");
		exit(1);
	}
	if (!ext2fs_group_desc_csum_verify(&sb, 0, &desc)) {
		printf("checksums should verify against gd_checksum\n");
		exit(1);
	}
	memset(sb.s_uuid, 0x30, sizeof(sb.s_uuid));
	print_csum("new_uuid", &sb, 0, &desc);
	if (ext2fs_group_desc_csum_verify(&sb, 0, &desc) != 0) {
		printf("checksums for different filesystems shouldn't match\n");
		exit(1);
	}
	csum1 = desc.bg_checksum = ext2fs_group_desc_csum(&sb, 0, &desc);
	print_csum("csum_new", &sb, 0, &desc);
	desc.bg_free_blocks_count = 1;
	csum2 = ext2fs_group_desc_csum(&sb, 0, &desc);
	print_csum("csum_blk", &sb, 0, &desc);
	if (csum1 == csum2) {
		printf("checksums for different data shouldn't match\n");
		exit(1);
	}

	return 0;
}
