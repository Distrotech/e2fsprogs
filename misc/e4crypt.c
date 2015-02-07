/*
 * e4crypt.c - ext4 encryption management utility
 *
 * Copyright (c) 2014 Google, Inc.
 *	SHA512 implementation if borrowed from libtomcrypt.
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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>
#include <asm/unistd.h>

#include "ext2fs/ext2_fs.h"

/* special process keyring shortcut IDs */
#define KEY_SPEC_THREAD_KEYRING		-1	/* - key ID for thread-specific
						   keyring */
#define KEY_SPEC_PROCESS_KEYRING	-2	/* - key ID for process-specific
						   keyring */
#define KEY_SPEC_SESSION_KEYRING	-3	/* - key ID for session-specific
						   keyring */
#define KEY_SPEC_USER_KEYRING		-4	/* - key ID for UID-specific
						   keyring */
#define KEY_SPEC_USER_SESSION_KEYRING	-5	/* - key ID for UID-session
						   keyring */
#define KEY_SPEC_GROUP_KEYRING		-6	/* - key ID for GID-specific
						   keyring */
#define KEY_SPEC_REQKEY_AUTH_KEY	-7	/* - key ID for assumed
						   request_key auth key */

/* keyring keyctl commands */
#define KEYCTL_UNLINK			9 /* unlink a key from a keyring */
#define KEYCTL_SEARCH			10 /* search for a key in a keyring */

/* keyring serial number type */
typedef int32_t key_serial_t;

/*
 * syscall wrappers
 */
key_serial_t add_key(const char *type,
		     const char *description,
		     const void *payload,
		     size_t plen,
		     key_serial_t ringid);
long keyctl_search(key_serial_t ringid,
		   const char *type,
		   const char *description,
		   key_serial_t
		   destringid);
long keyctl_unlink(key_serial_t id, key_serial_t ringid);

enum mode_flags {
	MODE_FLAG_NONE = 0,
	MODE_FLAG_POLICYSET = 1,
	MODE_FLAG_POLICYGET = 2,
	MODE_FLAG_POLICYDELETE = 4,
	MODE_FLAG_DANGER = 8,
	MODE_FLAG_INSERT_KEY = 16,
	MODE_FLAG_REMOVE_KEY = 32,
};

#define POLICY_WORK (MODE_FLAG_POLICYSET| \
		     MODE_FLAG_POLICYGET| \
		     MODE_FLAG_POLICYDELETE)
#define KEY_WORK (MODE_FLAG_INSERT_KEY| \
		  MODE_FLAG_REMOVE_KEY)

static enum mode_flags mode_flags = MODE_FLAG_NONE;

#define XATTR_NAME_ENCRYPTION_POLICY "encryption.policy"
#define EXT4_MAX_KEY_DESCRIPTION_SIZE 512
#define EXT4_MIN_KEY_DESCRIPTION_SIZE 16
#define EXT4_KEYREF_DELIMITER ((char)'.')
#define EXT4_POLICY_DELIMITER ((char)'#')

#define SHA512_LENGTH 64
static void hash_sha512(char *in, unsigned long in_size,
			char out[SHA512_LENGTH]);

#define MSG_USAGE              \
"Usage : e4crypt command [object] [options] [path1 ... pathN]\n"\
"	Where command might be one of the:\n"\
"	-g		Get policy value\n"\
"	-s policy	Set policy\n"\
"	-x		Delete policy\n"\
"	-a keyring	Insert a key into the keyring, defaults to\n"\
"			interactive passphrase mode.\n"\
"	-r keyring	Remove a key from the keyring (must use option '-k')\n"\
"OPTIONS:\n"\
"	-b hexstring	A modifier to '-a' command that inserts converts "\
"			provided hexstring into a byte array and uses it as a"\
"			key. It should be 32 bytes long at most (64 chars)."\
"	-p passphrase	A modifier to '-a' command that provides a passphrase"\
"			that is used for key generation. Currently we use 65K"\
"			iterations in pbkdf2 to derive a key."\
"NOTES:\n"\
"	-s command over a file requires '-W ignore-danger' command as well.\n"\
"	-g,-s and -x commands require at least one path.\n"\
"	Several paths can be provided, for which the same set of commands\n"\
"	will be executed.\n"\
"	-a commands defaults to passphrase if '-b hex' is not provided.\n"\
"	User can override key reference (i.e., a searchable string for\n"\
"	keyrings) by providing '-k keyref' modifier, otherwise, a hash value\n"\
"	of the key, converted to a string and truncated to 16 bytes, will be\n"\
"	used as keyref.\n"

static int do_policy_work(int argc,
			  char *argv[],
			  int path_start_index,
			  char *policy,
			  size_t policy_len);

static int do_key_work(char *keyring,
		       char *keyref,
		       char *hexvalue,
		       char *passphrase);

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
	char *keyring = NULL;
	char *keyref = NULL;
	char *hexvalue = NULL;
	char *passphrase = NULL;

	if (argc == 1)
		goto fail;
	while ((opt = getopt(argc, argv, "a:b:gk:p:r:s:xW:")) != -1) {
		switch (opt) {
		case 'a':
			/* Key insertion. */
			mode_flags |= MODE_FLAG_INSERT_KEY;
			keyring = optarg;
			break;
		case 'b':
			/* Key insertion in as-is mode, user provides a binary
			 * value of the key in hex format. */
			hexvalue = optarg;
			break;
		case 'g':
			/* Get the policy value. */
			mode_flags |= MODE_FLAG_POLICYGET;
			break;
		case 'k':
			/* Explicit key ref value - user provides us with an
			 * explicit value for the key reference, hence we do not
			 * do any ref derviation. */
			keyref = optarg;
			break;
		case 'r':
			/* Key removal. */
			mode_flags |= MODE_FLAG_REMOVE_KEY;
			keyring = optarg;
			break;
		case 'p':
			/* Passphrase. */
			passphrase = optarg;
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
	if (mode_flags & POLICY_WORK)
		return do_policy_work(argc, argv, optind, policy, policy_len);
	else if (mode_flags & KEY_WORK)
		return do_key_work(keyring, keyref, hexvalue, passphrase);
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

/* do_policy_work() - Policy work selector of what we actually do with a
 * policy. */
static int do_policy_work(int argc,
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

/* This function expect keyring value to be valid. */
static int get_keyring_id(char *keyring)
{
	int len = strlen(keyring);

	if (strncmp(keyring, "@t", len) == 0)
		return KEY_SPEC_THREAD_KEYRING;
	if (strncmp(keyring, "@p", len) == 0)
		return KEY_SPEC_PROCESS_KEYRING;
	if (strncmp(keyring, "@s", len) == 0)
		return KEY_SPEC_SESSION_KEYRING;
	if (strncmp(keyring, "@u", len) == 0)
		return KEY_SPEC_USER_KEYRING;
	if (strncmp(keyring, "@g", len) == 0)
		return KEY_SPEC_GROUP_KEYRING;
	if (strncmp(keyring, "@us", len) == 0)
		return KEY_SPEC_USER_SESSION_KEYRING;
}
static int is_keyring_valid(char *keyring)
{
	int len = strlen(keyring);

	if (strncmp(keyring, "@t", len) == 0 ||
	    strncmp(keyring, "@p", len) == 0 ||
	    strncmp(keyring, "@s", len) == 0 ||
	    strncmp(keyring, "@u", len) == 0 ||
	    strncmp(keyring, "@g", len) == 0 ||
	    strncmp(keyring, "@us", len) == 0)
		return 1;
	return 0;
}

void do_hash(char *src, int src_size, char *dst)
{
	hash_sha512(src, src_size, dst);
}

static int hex2byte(char *hexvalue, char *keyblob, size_t *keyblob_size)
{
	char *hexchars = "0123456789abcdef";
	size_t hexchars_len = strlen(hexchars);
	int i, max;
	char *h,*l;

	if (keyblob_size)
		*keyblob_size = 0;
	for (i = 0; i < strlen(hexvalue); i+=2) {
		h = memchr(hexchars, hexvalue[i], hexchars_len);
		l = memchr(hexchars, hexvalue[i + 1], hexchars_len);
		if (h == NULL || l == NULL) {
			*keyblob_size = 0;
			/* Well, its an invalid hex, exit.*/
			printf("Ivalid hex value (\"%s\").\n", hexvalue);
			return -EINVAL;
		}
		keyblob[i >> 1] = (char)(h - hexchars) << 4 +
			(char)(l - hexchars);
		if (keyblob_size)
			*keyblob_size += 1;
	}

	return 0;
}

static void derive_keyref(char *keyblob, size_t keyblob_size,
			 char *keyref, size_t keyref_size)
{
	char *hexchars = "0123456789abcdef";
	char buf[SHA512_LENGTH];
	int i;

	do_hash(keyblob, keyblob_size, buf);

	/* Convert digest to hex string */
	for (i = 0; i < (keyref_size - 1) >> 1; i++) {
		keyref[i << 1] = hexchars[(buf[i] & 0xf0) >> 4];
		keyref[(i << 1) + 1] =
			hexchars[buf[i] & 0x0f];
	}
	keyref[keyref_size - 1] = '\0';
}

static int key_insert_into_keyring(char *keyring,
				   char *keyblob,
				   int keyblob_size,
				   char *keyref)
{
	int ret;
	int keyring_id = get_keyring_id(keyring);
	struct ext4_encryption_key key;

	ret = (int)keyctl_search(keyring_id,
				 "logon",
				 keyref,
				 0);
	if (ret != -1) {
		printf("Key with that id already exist in the destination"
		       " keyring.\n");
		ret = 0;
		goto out;
	} else if ((ret == -1) && (errno != ENOKEY)) {
		int errnum = errno;
		syslog(LOG_ERR, "keyctl_search failed: %m errno=[%d]\n",
		       errnum);
		ret = (errnum < 0) ? errnum : errnum * -1;
		if (ret == -EINVAL)
			printf("Keyring %s is not available.\n", keyring);
		goto out;
	}
	key.mode = EXT4_ENCRYPTION_MODE_INVALID;
	/* Copy over whole array to copy zero bytes at the end too. */
	memcpy(key.raw, keyblob, EXT4_MAX_KEY_SIZE);
	key.size = keyblob_size;
	ret = add_key("logon", keyref, (void *)&key,
		      sizeof(struct ext4_encryption_key),
		      keyring_id);
	if (ret == -1) {
		ret = -errno;
		syslog(LOG_ERR, "Error adding key with keyref [%s]; ret = [%d] "
		       "\"%m\"\n", keyref, ret);
		if (ret == -EDQUOT)
			syslog(LOG_WARNING, "Error adding key to keyring -"
			      " keyring is full\n");
		printf("Failed to add key to keyring (%d).\n", ret);
		goto out;
	} else {
		printf("Key was successfuly inserted into %s keyring (ref=%s,"
			" size=%d, serial=%d)\n", keyring, keyref,
			keyblob_size, ret);
		ret = 0;
	}

out:
        return ret;
}

static int key_remove_from_keyring(char *keyring, char *keyref)
{
	int ret;
	int keyring_id = get_keyring_id(keyring);

	ret = (int)keyctl_search(keyring_id,
				 "logon",
				 keyref,
				 0);

	if (ret < 0) {
		ret = errno;
		syslog(LOG_ERR, "Failed to find key with ref [%s]: %m\n",
		       keyref);
		goto out;
	}
	ret = keyctl_unlink(ret, keyring_id);
	if (ret < 0) {
		ret = errno;
		syslog(LOG_ERR, "Failed to unlink key with ref [%s]: %s\n",
		       keyref, strerror(ret));
		goto out;
	}
	ret = 0;
	printf("Key [%s] was deleted from %s keyring.\n", keyref, keyring);
out:
        return ret;
}

static int key_insert_binary_blob(char *keyring,
				  char *keyref,
				  char *keyblob,
				  size_t keyblob_size)
{
	int ret = 0;
	char keyref_derived[EXT4_KEYREF_DERIVED_TOTAL_LEN + 1];
	char *keyref_provided = NULL;
	char *keyreference = keyref;

	/* Now obtain the keyref, i.e., a searchable string that identifies the
	 * key we are about to insert into keyring. */
	if (!keyref) {
		strncpy(keyref_derived,
			EXT4_KEYREF_LOGON_PREFIX,
			EXT4_KEYREF_LOGON_PREFIX_LEN);
		derive_keyref(keyblob, keyblob_size,
			      &keyref_derived[EXT4_KEYREF_LOGON_PREFIX_LEN],
			      EXT4_KEYREF_DERIVED_LEN + 1);
		keyreference = keyref_derived;
	} else {
		/* Check min length. Nothing serious, just to prevent users from
		 * using too short key refs. */
		if (strlen(keyref) < EXT4_KEYREF_MIN_LEN) {
			printf("Keyref is too short, at least %d chars are"
			       " required.\n", EXT4_KEYREF_MIN_LEN);
			ret = -EINVAL;
			goto out;
		}

		keyref_provided = malloc(strlen(keyref) +
					 EXT4_KEYREF_LOGON_PREFIX_LEN + 1);
		if (!keyref_provided) {
			printf("Unable to allocate memory for key reference.\n");
			ret = -ENOMEM;
			goto out;
		}

		/* copy prefix */
		strncpy(keyref_provided,
			EXT4_KEYREF_LOGON_PREFIX,
			EXT4_KEYREF_LOGON_PREFIX_LEN);
		strncpy(&keyref_provided[EXT4_KEYREF_LOGON_PREFIX_LEN],
			keyref,
			strlen(keyref));
		keyref_provided[EXT4_KEYREF_LOGON_PREFIX_LEN + strlen(keyref)] =
			'\0';
		keyreference = keyref_provided;
	}

	ret = key_insert_into_keyring(keyring,
				      keyblob, keyblob_size,
				      keyreference);

out:
	return ret;
}

static int key_insert_hexstring(char *keyring,
				char *keyref,
				char *hexvalue)
{
	char keyblob[EXT4_MAX_KEY_SIZE];
	size_t keyblob_size = 0;
	int ret = 0;

	if ((strlen(hexvalue) >> 1) > EXT4_MAX_KEY_SIZE) {
		printf("Hex value length is too long. Maximum supported key"
		       " length is %d.\n", EXT4_MAX_KEY_SIZE);
		return -EINVAL;
	}

	memset(keyblob, 0, EXT4_MAX_KEY_SIZE);
	ret = hex2byte(hexvalue, keyblob, &keyblob_size);
	if (ret)
		goto out;

	/* All keys inserted from user-space are not used directly to encrypt
	 * data. They are only used to wrap Data Encryption Keys with CTR mode.
	 * Which means, we need at least 256 bit key. */
	if (keyblob_size < EXT4_AES_256_CTR_KEY_SIZE) {
		printf("The length of the key is smaller than minimal requred"
		       " (%d < %d).Consider using passphrase insead.\n",
		       (int)keyblob_size,
		       EXT4_AES_256_CTR_KEY_SIZE);
		goto out;
	}

	ret = key_insert_binary_blob(keyring, keyref, keyblob, keyblob_size);

out:
	return ret;
}

static int disable_echo(struct termios *saved_settings)
{
	struct termios current_settings;
	int rc = 0;

	rc = tcgetattr(0, &current_settings);
	if (rc)
		return rc;
	*saved_settings =
		current_settings;
	current_settings.c_lflag &= ~ECHO;
	rc = tcsetattr(0, TCSANOW, &current_settings);

	return rc;
}

static int enable_echo(struct termios *saved_settings)
{
	return tcsetattr(0, TCSANOW, saved_settings);
}

/* Note, we are producing a 32 bit key at most, since the key is needed for
 * wrapped key packet protection in CTR mode. */
static void pbkdf2_sha512(char *passphrase,
			  char *salt,
			  int count,
			  char derived_key[EXT4_AES_256_CTR_KEY_SIZE])
{
	char buf[SHA512_LENGTH + EXT4_MAX_PASSWORD_LENGTH];
	char tempbuf[SHA512_LENGTH], final[SHA512_LENGTH];
	char saltbuf[EXT4_DEFAULT_SALT_SIZE + EXT4_MAX_PASSWORD_LENGTH];
	int buf_len = SHA512_LENGTH + strlen(passphrase);
	int saltbuf_len = EXT4_DEFAULT_SALT_SIZE + strlen(passphrase);
	int i, j;
	uint32_t *final_u32 = (uint32_t *)final;
	uint32_t *temp_u32 = (uint32_t *)tempbuf;

	memset(final, 0, SHA512_LENGTH);
	/* Prepare intermediate blob .*/
	memcpy(&buf[SHA512_LENGTH], passphrase, strlen(passphrase));
	/* Init initial blob. */
	hex2byte(salt, saltbuf, NULL);
	memcpy(&saltbuf[EXT4_DEFAULT_SALT_SIZE], passphrase,
	       strlen(passphrase));
	for (i = 0; i < count; i++) {
		if (i == 0) {
			do_hash(saltbuf, saltbuf_len, tempbuf);
		} else {
			do_hash(buf, buf_len, tempbuf);
		}
		for (j = 0; j < (SHA512_LENGTH >> 2); j++) {
			final_u32[j] = final_u32[j] ^ temp_u32[j];
		}
		memcpy(buf, tempbuf, SHA512_LENGTH);
	}

	/* Copy required bytes. */
	memcpy(derived_key, final, EXT4_AES_256_CTR_KEY_SIZE);
}

static int key_insert_passphrase(char *keyring,
				 char *keyref,
				 char *_passphrase)
{
	int ret = 0;
	char *p;
	char keyblob[EXT4_AES_256_CTR_KEY_SIZE];
	char *passphrase = NULL;
	size_t salt_byte_size;
        struct termios current_settings;

	if (!_passphrase) {
		passphrase = malloc(EXT4_MAX_PASSWORD_LENGTH + 2);
		if (!passphrase) {
			ret = -ENOMEM;
			printf("Unable to allocate memory for password.\n");
			goto out;
		}
		printf("Passphrase:");
		disable_echo(&current_settings);
		if (fgets(passphrase,
			  EXT4_MAX_PASSWORD_LENGTH + 2,
			  stdin) == NULL) {
			enable_echo(&current_settings);
			printf("\n");
			ret = -ENOKEY;
			goto out_free_passphrase;
		}
		enable_echo(&current_settings);
		p = strrchr(passphrase, '\n');
		if (p) {
			*p = '\0';
		} else {
			printf("Cannot finde cr\n");
		}
		printf("\n");
		if (strlen(passphrase) > EXT4_MAX_PASSWORD_LENGTH) {
			fprintf(stderr,"Passphrase is too long. Use at most %u "
				"characters long passphrase.\n",
				EXT4_MAX_PASSWORD_LENGTH);
			ret = -EINVAL;
			goto out_free_passphrase;
		}
	} else {
		passphrase = _passphrase;
	}

	/* TODO(ildar): This is the place where we should override default
	 * salt value. */
	pbkdf2_sha512(passphrase, EXT4_DEFAULT_SALT,
		      EXT4_PBKDF2_ITERATIONS, keyblob);
	ret = key_insert_binary_blob(keyring, keyref,
				     keyblob,
				     EXT4_AES_256_CTR_KEY_SIZE);
out_free_passphrase:
	if (!_passphrase)
		free(passphrase);

out:
	return ret;
}


static int do_key_insert(char *keyring,
			 char *keyref,
			 char *hexvalue,
			 char *passphrase)
{
	/* Check if we should do "AS-IS" insert or based on passphrase */
	if (hexvalue) {
		/* As-is approach, that is, user specifies hex representation of
		 * the key. */
		return key_insert_hexstring(keyring, keyref, hexvalue);
	} else {
		/* Passphrase approach, note, if '-p' is not used user will be
		 * promted to type in a passphrase. */
		return key_insert_passphrase(keyring, keyref, passphrase);
	}
	return -EINVAL;
}

static int do_key_remove(char *keyring,
			 char *keyref)
{
	if (keyref) {
		return key_remove_from_keyring(keyring, keyref);
	} else {
		printf("Cannot delete a key without key reference.\n");
		return -ENOKEY;
	}
	return -EINVAL;
}

static int do_key_work(char *keyring,
		       char *keyref,
		       char *hexvalue,
		       char *passphrase)
{
	int ret = 0;

	/* Validate keyring*/
	if (!is_keyring_valid(keyring)) {
		printf("Invalid keyring name (%s). Consult keyctl manual for proper"
		       " names.\n", keyring);
		return -EINVAL;
	}

	if (mode_flags & MODE_FLAG_INSERT_KEY) {
		ret = do_key_insert(keyring, keyref, hexvalue, passphrase);
	} else if (mode_flags & MODE_FLAG_REMOVE_KEY) {
		ret = do_key_remove(keyring, keyref);
		if (ret)
			printf("Failed to remove key %s from %s.\n",
			       keyref, keyring);
	}

	return ret;
}

long keyctl(int cmd, ...)
{
	va_list va;
	unsigned long arg2, arg3, arg4, arg5;

	va_start(va, cmd);
	arg2 = va_arg(va, unsigned long);
	arg3 = va_arg(va, unsigned long);
	arg4 = va_arg(va, unsigned long);
	arg5 = va_arg(va, unsigned long);
	va_end(va);
	return syscall(__NR_keyctl,
		       cmd, arg2, arg3, arg4, arg5);
}

key_serial_t add_key(const char *type,
		     const char *description,
		     const void *payload,
		     size_t plen,
		     key_serial_t ringid)
{
	return syscall(__NR_add_key,
		       type, description, payload, plen,
		       ringid);
}

long keyctl_search(key_serial_t ringid,
		   const char *type,
		   const char *description,
		   key_serial_t
		   destringid)
{
	return keyctl(KEYCTL_SEARCH, ringid, type, description,
		      destringid);
}

long keyctl_unlink(key_serial_t id, key_serial_t ringid)
{
	return keyctl(KEYCTL_UNLINK, id, ringid);
}

/* SHA512 Implementation (copied from libtomcrypt) */
/* the K array */
#define CONST64(n) n
typedef unsigned long long ulong64;
static const ulong64 K[80] = {
	CONST64(0x428a2f98d728ae22), CONST64(0x7137449123ef65cd),
	CONST64(0xb5c0fbcfec4d3b2f), CONST64(0xe9b5dba58189dbbc),
	CONST64(0x3956c25bf348b538), CONST64(0x59f111f1b605d019),
	CONST64(0x923f82a4af194f9b), CONST64(0xab1c5ed5da6d8118),
	CONST64(0xd807aa98a3030242), CONST64(0x12835b0145706fbe),
	CONST64(0x243185be4ee4b28c), CONST64(0x550c7dc3d5ffb4e2),
	CONST64(0x72be5d74f27b896f), CONST64(0x80deb1fe3b1696b1),
	CONST64(0x9bdc06a725c71235), CONST64(0xc19bf174cf692694),
	CONST64(0xe49b69c19ef14ad2), CONST64(0xefbe4786384f25e3),
	CONST64(0x0fc19dc68b8cd5b5), CONST64(0x240ca1cc77ac9c65),
	CONST64(0x2de92c6f592b0275), CONST64(0x4a7484aa6ea6e483),
	CONST64(0x5cb0a9dcbd41fbd4), CONST64(0x76f988da831153b5),
	CONST64(0x983e5152ee66dfab), CONST64(0xa831c66d2db43210),
	CONST64(0xb00327c898fb213f), CONST64(0xbf597fc7beef0ee4),
	CONST64(0xc6e00bf33da88fc2), CONST64(0xd5a79147930aa725),
	CONST64(0x06ca6351e003826f), CONST64(0x142929670a0e6e70),
	CONST64(0x27b70a8546d22ffc), CONST64(0x2e1b21385c26c926),
	CONST64(0x4d2c6dfc5ac42aed), CONST64(0x53380d139d95b3df),
	CONST64(0x650a73548baf63de), CONST64(0x766a0abb3c77b2a8),
	CONST64(0x81c2c92e47edaee6), CONST64(0x92722c851482353b),
	CONST64(0xa2bfe8a14cf10364), CONST64(0xa81a664bbc423001),
	CONST64(0xc24b8b70d0f89791), CONST64(0xc76c51a30654be30),
	CONST64(0xd192e819d6ef5218), CONST64(0xd69906245565a910),
	CONST64(0xf40e35855771202a), CONST64(0x106aa07032bbd1b8),
	CONST64(0x19a4c116b8d2d0c8), CONST64(0x1e376c085141ab53),
	CONST64(0x2748774cdf8eeb99), CONST64(0x34b0bcb5e19b48a8),
	CONST64(0x391c0cb3c5c95a63), CONST64(0x4ed8aa4ae3418acb),
	CONST64(0x5b9cca4f7763e373), CONST64(0x682e6ff3d6b2b8a3),
	CONST64(0x748f82ee5defb2fc), CONST64(0x78a5636f43172f60),
	CONST64(0x84c87814a1f0ab72), CONST64(0x8cc702081a6439ec),
	CONST64(0x90befffa23631e28), CONST64(0xa4506cebde82bde9),
	CONST64(0xbef9a3f7b2c67915), CONST64(0xc67178f2e372532b),
	CONST64(0xca273eceea26619c), CONST64(0xd186b8c721c0c207),
	CONST64(0xeada7dd6cde0eb1e), CONST64(0xf57d4f7fee6ed178),
	CONST64(0x06f067aa72176fba), CONST64(0x0a637dc5a2c898a6),
	CONST64(0x113f9804bef90dae), CONST64(0x1b710b35131c471b),
	CONST64(0x28db77f523047d84), CONST64(0x32caab7b40c72493),
	CONST64(0x3c9ebe0a15c9bebc), CONST64(0x431d67c49c100d4c),
	CONST64(0x4cc5d4becb3e42b6), CONST64(0x597f299cfc657e2a),
	CONST64(0x5fcb6fab3ad6faec), CONST64(0x6c44198c4a475817)
};
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y))
#define S(x, n)         ROR64c(x, n)
#define R(x, n)         (((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((ulong64)n))
#define Sigma0(x)       (S(x, 28) ^ S(x, 34) ^ S(x, 39))
#define Sigma1(x)       (S(x, 14) ^ S(x, 18) ^ S(x, 41))
#define Gamma0(x)       (S(x, 1) ^ S(x, 8) ^ R(x, 7))
#define Gamma1(x)       (S(x, 19) ^ S(x, 61) ^ R(x, 6))
#define RND(a,b,c,d,e,f,g,h,i)\
		t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];\
		t1 = Sigma0(a) + Maj(a, b, c);\
		d += t0;\
		h  = t0 + t1;
#define STORE64H(x, y) \
	do { \
		(y)[0] = (unsigned char)(((x)>>56)&255);\
		(y)[1] = (unsigned char)(((x)>>48)&255);\
		(y)[2] = (unsigned char)(((x)>>40)&255);\
		(y)[3] = (unsigned char)(((x)>>32)&255);\
		(y)[4] = (unsigned char)(((x)>>24)&255);\
		(y)[5] = (unsigned char)(((x)>>16)&255);\
		(y)[6] = (unsigned char)(((x)>>8)&255);\
		(y)[7] = (unsigned char)((x)&255); } while(0)

#define LOAD64H(x, y)\
	do {x = \
		(((ulong64)((y)[0] & 255)) << 56) |\
		(((ulong64)((y)[1] & 255)) << 48) |\
		(((ulong64)((y)[2] & 255)) << 40) |\
		(((ulong64)((y)[3] & 255)) << 32) |\
		(((ulong64)((y)[4] & 255)) << 24) |\
		(((ulong64)((y)[5] & 255)) << 16) |\
		(((ulong64)((y)[6] & 255)) << 8) |\
		(((ulong64)((y)[7] & 255)));\
	} while(0)

#define ROR64c(word,i) ({ \
	ulong64 __ROR64c_tmp = word; \
	__asm__ ("rorq %2, %0" : \
		 "=r" (__ROR64c_tmp) : \
		 "0" (__ROR64c_tmp), \
		 "J" (i)); \
	__ROR64c_tmp; })

struct sha512_state {
	ulong64  length, state[8];
	unsigned long curlen;
	unsigned char buf[128];
};

/* This is a highly simplified version from libtomcrypt */
struct hash_state {
	struct sha512_state sha512;
};

static void sha512_compress(struct hash_state * md, const unsigned char *buf)
{
	ulong64 S[8], W[80], t0, t1;
	int i;

	/* copy state into S */
	for (i = 0; i < 8; i++) {
		S[i] = md->sha512.state[i];
	}

	/* copy the state into 1024-bits into W[0..15] */
	for (i = 0; i < 16; i++) {
		LOAD64H(W[i], buf + (8*i));
	}

	/* fill W[16..79] */
	for (i = 16; i < 80; i++) {
		W[i] = Gamma1(W[i - 2]) + W[i - 7] +
			Gamma0(W[i - 15]) + W[i - 16];
	}

	for (i = 0; i < 80; i += 8) {
		RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i+0);
		RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],i+1);
		RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],i+2);
		RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],i+3);
		RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],i+4);
		RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],i+5);
		RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],i+6);
		RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],i+7);
	}

	 /* feedback */
	for (i = 0; i < 8; i++) {
		md->sha512.state[i] = md->sha512.state[i] + S[i];
	}
}

static void sha512_init(struct hash_state * md)
{
	md->sha512.curlen = 0;
	md->sha512.length = 0;
	md->sha512.state[0] = CONST64(0x6a09e667f3bcc908);
	md->sha512.state[1] = CONST64(0xbb67ae8584caa73b);
	md->sha512.state[2] = CONST64(0x3c6ef372fe94f82b);
	md->sha512.state[3] = CONST64(0xa54ff53a5f1d36f1);
	md->sha512.state[4] = CONST64(0x510e527fade682d1);
	md->sha512.state[5] = CONST64(0x9b05688c2b3e6c1f);
	md->sha512.state[6] = CONST64(0x1f83d9abfb41bd6b);
	md->sha512.state[7] = CONST64(0x5be0cd19137e2179);
}

static void sha512_done(struct hash_state * md, unsigned char *out)
{
	int i;

	/* increase the length of the message */
	md->sha512.length += md->sha512.curlen * CONST64(8);

	/* append the '1' bit */
	md->sha512.buf[md->sha512.curlen++] = (unsigned char)0x80;

	/* if the length is currently above 112 bytes we append zeros then
	 * compress. Then we can fall back to padding zeros and length encoding
	 * like normal. */
	if (md->sha512.curlen > 112) {
		while (md->sha512.curlen < 128) {
			md->sha512.buf[md->sha512.curlen++] = (unsigned char)0;
		}
		sha512_compress(md, md->sha512.buf);
		md->sha512.curlen = 0;
	}

	/* pad upto 120 bytes of zeroes note: that from 112 to 120 is the 64 MSB
	 * of the length. We assume that you won't hash > 2^64 bits of data. */
	while (md->sha512.curlen < 120) {
		md->sha512.buf[md->sha512.curlen++] = (unsigned char)0;
	}

	/* store length */
	STORE64H(md->sha512.length, md->sha512.buf + 120);
	sha512_compress(md, md->sha512.buf);

	/* copy output */
	for (i = 0; i < 8; i++) {
		STORE64H(md->sha512.state[i], out+(8 * i));
	}
}

#define MIN(x, y) ( ((x)<(y))?(x):(y) )
#define SHA512_BLOCKSIZE 512
static void sha512_process(struct hash_state * md,
			   unsigned char *in,
			   unsigned long inlen)
{
	unsigned long n;

	while (inlen > 0) {
		if (md->sha512.curlen == 0 && inlen >= SHA512_BLOCKSIZE) {
			sha512_compress(md, in);
			md->sha512.length += SHA512_BLOCKSIZE * 8;
			in += SHA512_BLOCKSIZE;
			inlen -= SHA512_BLOCKSIZE;
		} else {
			n = MIN(inlen, (SHA512_BLOCKSIZE - md->sha512.curlen));
			memcpy(md->sha512.buf + md->sha512.curlen,
			       in, (size_t)n);
			md->sha512.curlen += n;
			in += n;
			inlen -= n;
			if (md->sha512.curlen == SHA512_BLOCKSIZE) {
				sha512_compress(md, md->sha512.buf);
				md->sha512.length += SHA512_BLOCKSIZE * 8;
				md->sha512.curlen = 0;
			}
		}
	}
}

static void hash_sha512(char *in, unsigned long in_size,
			char out[SHA512_LENGTH])
{
	struct hash_state md;

	sha512_init(&md);
	sha512_process(&md, in, in_size);
	sha512_done(&md, out);
}
