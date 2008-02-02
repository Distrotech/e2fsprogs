/*
  File: linux/ext2_ext_attr.h

  On-disk format of extended attributes for the ext2 filesystem.

  (C) 2000 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

#ifndef _EXT2_EXT_ATTR_H
#define _EXT2_EXT_ATTR_H
/* Magic value in attribute blocks */
#define EXT2_EXT_ATTR_MAGIC_v1		0xEA010000
#define EXT2_EXT_ATTR_MAGIC		0xEA020000

/* Maximum number of references to one attribute block */
#define EXT2_EXT_ATTR_REFCOUNT_MAX	1024

#define XATTR_CREATE    0x1     /* set value, fail if attr already exists */
#define XATTR_REPLACE   0x2     /* set value, fail if attr does not exist */

struct ext2_ext_attr_header {
	__u32	h_magic;	/* magic number for identification */
	__u32	h_refcount;	/* reference count */
	__u32	h_blocks;	/* number of disk blocks used */
	__u32	h_hash;		/* hash value of all attributes */
	__u32	h_reserved[4];	/* zero right now */
};

struct ext2_ext_attr_entry {
	__u8	e_name_len;	/* length of name */
	__u8	e_name_index;	/* attribute name index */
	__u16	e_value_offs;	/* offset in disk block of value */
	__u32	e_value_block;	/* disk block attribute is stored on (n/i) */
	__u32	e_value_size;	/* size of attribute value */
	__u32	e_hash;		/* hash value of name and value */
#if 1
	char	e_name[0];	/* attribute name */
#endif
};

#define BHDR(block) ((struct ext2_ext_attr_header *) block)
#define IHDR(inode)			   	\
	((__u32 *) ((char *)inode +	     	\
		    EXT2_GOOD_OLD_INODE_SIZE +  \
		    (inode)->i_extra_isize))
#define ENTRY(ptr) ((struct ext2_ext_attr_entry *)(ptr))

/* Name indexes */
#define EXT2_ATTR_INDEX_USER		    	1
#define EXT2_ATTR_INDEX_POSIX_ACL_ACCESS	2
#define EXT2_ATTR_INDEX_POSIX_ACL_DEFAULT	3
#define EXT2_ATTR_INDEX_TRUSTED			4
#define EXT2_ATTR_INDEX_LUSTRE			5
#define EXT2_ATTR_INDEX_SECURITY		6
#define EXT2_ATTR_INDEX_MAX			7

#define EXT2_ATTR_INDEX_USER_PREFIX		 "user."
#define EXT2_ATTR_INDEX_POSIX_ACL_ACCESS_PREFIX	 "system.posix_acl_access"
#define EXT2_ATTR_INDEX_POSIX_ACL_DEFAULT_PREFIX "system.posix_acl_default"
#define EXT2_ATTR_INDEX_TRUSTED_PREFIX		 "trusted."
#define EXT2_ATTR_INDEX_LUSTRE_PREFIX		 "lustre."
#define EXT2_ATTR_INDEX_SECURITY_PREFIX		 "security."

#define EXT2_ATTR_PREFIX(index) (index ## _PREFIX)
#define EXT2_ATTR_PREFIX_LEN(index) (index ## _PRE_LEN)

#define EXT2_EXT_ATTR_PAD_BITS		2
#define EXT2_EXT_ATTR_PAD		((unsigned) 1<<EXT2_EXT_ATTR_PAD_BITS)
#define EXT2_EXT_ATTR_ROUND		(EXT2_EXT_ATTR_PAD-1)
#define EXT2_EXT_ATTR_LEN(name_len) \
	(((name_len) + EXT2_EXT_ATTR_ROUND + \
	sizeof(struct ext2_ext_attr_entry)) & ~EXT2_EXT_ATTR_ROUND)
#define EXT2_EXT_ATTR_NEXT(entry) \
	( (struct ext2_ext_attr_entry *)( \
	  (char *)(entry) + EXT2_EXT_ATTR_LEN((entry)->e_name_len)) )
#define EXT2_EXT_ATTR_SIZE(size) \
	(((size) + EXT2_EXT_ATTR_ROUND) & ~EXT2_EXT_ATTR_ROUND)
#define EXT2_EXT_IS_LAST_ENTRY(entry) (*((__u32 *)(entry)) == 0UL)
#define EXT2_EXT_ATTR_NAME(entry) \
	(((char *) (entry)) + sizeof(struct ext2_ext_attr_entry))
#define EXT2_XATTR_LEN(name_len) \
	(((name_len) + EXT2_EXT_ATTR_ROUND + \
	sizeof(struct ext2_xattr_entry)) & ~EXT2_EXT_ATTR_ROUND)
#define EXT2_XATTR_SIZE(size) \
	(((size) + EXT2_EXT_ATTR_ROUND) & ~EXT2_EXT_ATTR_ROUND)

#ifdef __KERNEL__
# ifdef CONFIG_EXT2_FS_EXT_ATTR
extern int ext2_get_ext_attr(struct inode *, const char *, char *, size_t, int);
extern int ext2_set_ext_attr(struct inode *, const char *, char *, size_t, int);
extern void ext2_ext_attr_free_inode(struct inode *inode);
extern void ext2_ext_attr_put_super(struct super_block *sb);
extern int ext2_ext_attr_init(void);
extern void ext2_ext_attr_done(void);
# else
#  define ext2_get_ext_attr NULL
#  define ext2_set_ext_attr NULL
# endif
#endif  /* __KERNEL__ */
#endif  /* _EXT2_EXT_ATTR_H */
