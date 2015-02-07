/*
 * e4crypt.c - ext4 encryption management utility
 *
 * Copyright (c) 2014 Google, Inc.
 *
 * Authors: Michael Halcrow <mhalcrow@google.com>,
 *	Ildar Muslukhov <ildarm@google.com>
 */

#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* All xattrs are limited in size to 4K (even less, since some space is taken
 * by headers and xattr name). To simplify we limit it to 4K, if we fail to set
 * an xattr setxattr will return appropriate error code. */
#define XATTR_MAX_SIZE 4096

#include "config.h"
#include <errno.h>
#include <getopt.h>
#include <dirent.h>
#include <errno.h>
#include <linux/xattr.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

enum mode_flags {
	MODE_FLAG_NONE = 0,
	MODE_FLAG_POLICYSET = 1,
	MODE_FLAG_POLICYGET = 2,
	MODE_FLAG_POLICYDELETE = 4,
	MODE_FLAG_DANGER = 8,
};

static enum mode_flags mode_flags = MODE_FLAG_NONE;

#define XATTR_NAME_ENCRYPTION_POLICY "encryption.policy"
#define EXT4_MAX_KEY_DESCRIPTION_SIZE 512
#define EXT4_MIN_KEY_DESCRIPTION_SIZE 16
#define EXT4_KEYREF_DELIMITER ((char)'.')
#define EXT4_POLICY_DELIMITER ((char)'#')

#define MSG_USAGE              \
"Usage : e4crypt command [policy] [path1 ... pathN]\n"\
"	Where command might be one of the:\n"\
"	-g		Get policy value\n"\
"	-s policy	Set policy\n"\
"	-x		Delete policy\n"\
"NOTES:\n"\
"	-s command over a file requires '-W ignore-danger' command as well.\n"\
"	-g,-s and -x commands require at least one path.\n"\
"	Several paths can be provided, for which the same set of commands\n"\
"	will be executed.\n"

static int do_work(int argc,
		   char *argv[],
		   int path_start_index,
		   char *policy,
		   size_t policy_len);

/*
 * main() -            Ext4 crypto management tool.
 *
 * @argc:              the number of parameter.
 * @argv[]:            the pointer array of parameter.
 */
int main(int argc, char *argv[])
{
	int opt;
	char *policy = NULL;
	size_t policy_len = 0;

	if (argc == 1)
		goto fail;

	while ((opt = getopt(argc, argv, "gs:xW:")) != -1) {
		switch (opt) {
		case 'g':
			/* Get the policy value. */
			mode_flags |= MODE_FLAG_POLICYGET;
			break;
		case 's':
			/* Set policy value.*/
			mode_flags |= MODE_FLAG_POLICYSET;
			/* Save policy to pass it later to sub-routines. */
			policy = optarg;
			policy_len = strlen(optarg);
			break;
		case 'x':
			/* Remobe encryption policy. */
			mode_flags |= MODE_FLAG_POLICYDELETE;
			break;
		case 'W':
			/* Required flag to set a policy over a file.
			 * NOTE: We require such flag in order to avoid
			 * confusion with disappeared encryption due to use of
			 * swap files by some apps (e.g., vim, emacs). That is,
			 * a user sets the policy over a file HAS to be aware of
			 * this possibility. */
			mode_flags |= MODE_FLAG_DANGER;
			if (strcmp("ignore-danger", optarg) != 0) {
				goto fail;
			}
			break;
		default:
			goto fail;
		}
	}

	return do_work(argc, argv, optind, policy, policy_len);
fail:
	printf(MSG_USAGE);
	return 1;
}

/* Validate that all path items are available and accessible. */
static int is_path_valid(int argc,
			 char *argv[],
			 int path_start_index)
{
	int ret = 0, i;
	int valid = 1;

	if (path_start_index == argc) {
		printf("At least one path option must be provided.\n");
		return 0;
	}

	for (i = path_start_index; i < argc; i++) {
		ret = access(argv[i], W_OK);
		if (ret) {
			  printf("%s: %s\n",strerror(errno), argv[i]);
			  valid = 0;
		}
	}

	return valid;
}

/* Gets policy for all items in path option */
static int do_policy_get(int argc,
			 char *argv[],
			 int path_start_index)
{
	int ret = 0, i;
	char buffer[XATTR_MAX_SIZE];
	size_t ret_size;

	if (is_path_valid(argc, argv, path_start_index))
	{
		for (i = path_start_index; i < argc; i++) {
			ret_size = getxattr(argv[i],
					    XATTR_NAME_ENCRYPTION_POLICY,
					    buffer, sizeof(buffer) - 1);
			if (ret_size == -1) {
				printf("%s: %s\n",strerror(errno), argv[i]);
			} else {
				buffer[ret_size] = '\0';
				printf("Encryption policy for %s is: %s\n",
				       argv[i], buffer);
			}
		}
	}

	return ret;
}

/* Checks whether the policy provided is valid */
static int is_keyref_valid(char *keyref, size_t keyref_len)
{
	char *period;
	size_t key_location_len = 0;

	/* Key ref must have a key and location delimiter character. */
	period = memchr(keyref, EXT4_KEYREF_DELIMITER, keyref_len);
	if (!period)
		return 0;

	/* period must be >= keyref. */
	key_location_len = period - keyref;

	if (strncmp(keyref, "@t", key_location_len) == 0 ||
	    strncmp(keyref, "@p", key_location_len) == 0 ||
	    strncmp(keyref, "@s", key_location_len) == 0 ||
	    strncmp(keyref, "@u", key_location_len) == 0 ||
	    strncmp(keyref, "@g", key_location_len) == 0 ||
	    strncmp(keyref, "@us", key_location_len) == 0)
		return 1;

	return 0;
}

static int is_policy_valid(char *policy,
			   size_t policy_len)
{
	char *key_ref_ptr = policy;
	char *next = policy;
	size_t key_ref_len = 0;
	size_t next_pos = 0;

	/* Validate key references' format. */
	do {
		next = memchr(next, EXT4_POLICY_DELIMITER,
			      policy_len - next_pos);
		/* next points to policy delimiter char, if found */
		if (next) {
			/* next should be >= than key_ref_ptr and should point
			 * to policy delimiter. */
			key_ref_len = next - key_ref_ptr;
			next++; /* Move over the delimiter char. */
			/* Calculate next position from the beginning of the
			 * policy. */
			next_pos = key_ref_ptr - policy;
		} else {
			/* If this is the last key reference, then use the end
			 * of the policy string as the end of the key reference.
			 */
			key_ref_len = &policy[policy_len] - key_ref_ptr;
			/* NOTE: We do not assign next_pos in this branch,
			 * because it does not matter. We gona exit the loop
			 * anyway. */
		}
		/* Validate key reference format. */
		if (!is_keyref_valid(key_ref_ptr, key_ref_len)) {
			return 0;
                }
		key_ref_ptr = next;
	} while (key_ref_ptr);

	return 1;
}

static int is_dir_empty(char *dirname)
{
	int n = 0;
	struct dirent *d;
	DIR *dir;

	dir = opendir(dirname);
	while ((d = readdir(dir)) != NULL) {
		if (++n > 2)
			break;
	}
	closedir(dir);
	return n <= 2;
}

static int do_policy_set(int argc,
			 char *argv[],
			 int path_start_index,
			 char *policy,
			 size_t policy_len)
{
	char buffer[XATTR_MAX_SIZE];
	int change, i;
	struct stat st;
	size_t ret_size;
	int flags;

	if (!is_policy_valid(policy, policy_len)) {
		printf("Policy has invalid format.\n");
		return -EINVAL;
	}

	if (is_path_valid(argc, argv, path_start_index)) {
		for (i = path_start_index; i < argc; i++) {
			change = 0;
			/* Check if we can set the policy */
			ret_size = getxattr(argv[i],
					    XATTR_NAME_ENCRYPTION_POLICY,
					    buffer, sizeof(buffer) - 1);

			if (ret_size == -1 && errno == ENODATA)
				flags = XATTR_CREATE;
			else
				flags = XATTR_REPLACE;
			/* Check if the file or directory is empty. */
			stat(argv[i], &st);
			if (S_ISREG(st.st_mode) && st.st_size == 0) {
				if (mode_flags & MODE_FLAG_DANGER) {
					change = 1;
				} else {
					printf("Cannot set policy directly on a file without W parameter (%s).\n",
					       argv[i]);
				}
			} else if (S_ISDIR(st.st_mode) &&
				   is_dir_empty(argv[i])) {
				change = 1;
			} else {
				printf("Policy change on a non-empty file/directory is not supported (%s).\n",
				       argv[i]);
			}

			if (change) {
				ret_size = setxattr(argv[i],
						    XATTR_NAME_ENCRYPTION_POLICY,
						    policy,
						    policy_len,
						    flags);
				if (!ret_size) {
					printf("Encryption policy for %s is set to %s\n",
					       argv[i], policy);
				} else {
					printf("Failed to set encryption policy for %s: %s\n",
					       argv[i], strerror(errno));
				}
			}
		}

	}
}

static int do_policy_delete(int argc, char *argv[], int path_start_index)
{
	char buffer[XATTR_MAX_SIZE];
	int change, i;
	struct stat st;
	size_t ret_size;
	int flags;

	if (is_path_valid(argc, argv, path_start_index)) {
		for (i = path_start_index; i < argc; i++) {
			change = 0;
			/* Check if the file or directory is empty. */
			stat(argv[i], &st);
			if (S_ISREG(st.st_mode) && st.st_size == 0) {
				change = 1;
			} else if (S_ISDIR(st.st_mode) &&
				   is_dir_empty(argv[i])) {
				change = 1;
			} else {
				printf("Policy removal on a non-empty file and directory is not supported.\n");
			}

			if (change) {
				ret_size = removexattr(argv[i],
						       XATTR_NAME_ENCRYPTION_POLICY);
				if (!ret_size) {
					printf("Encryption policy for %s is removed.\n",
					       argv[i]);
				} else {
					printf("Failed to remove encryption policy for %s: %s\n",
					       argv[i], strerror(errno));
				}
			}
		}

	}
}

/* do_work() - The main selector of what we actually do. */
static int do_work(int argc,
		   char *argv[],
		   int path_start_index,
		   char *policy,
		   size_t policy_len)
{
	int ret = 0;

	if (mode_flags & MODE_FLAG_POLICYGET) {
		ret = do_policy_get(argc, argv, path_start_index);
	} else if (mode_flags & MODE_FLAG_POLICYSET) {
		ret = do_policy_set(argc, argv, path_start_index,
				    policy, policy_len);
	} else if (mode_flags & MODE_FLAG_POLICYDELETE) {
		ret = do_policy_delete(argc, argv, path_start_index);
	}
	return ret;
}
