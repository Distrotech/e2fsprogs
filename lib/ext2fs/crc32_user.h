/*
 * Defines macros and types required by crc32 code undefined in user space.
 */
#ifndef _LINUX_CRC32_USER_H
#define _LINUX_CRC32_USER_H
#include <linux/types.h>

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define __swab32(x) \
({ \
        __u32 __x = (x); \
        ((__u32)( \
                (((__u32)(__x) & (__u32)0x000000ffUL) << 24) | \
                (((__u32)(__x) & (__u32)0x0000ff00UL) <<  8) | \
                (((__u32)(__x) & (__u32)0x00ff0000UL) >>  8) | \
                (((__u32)(__x) & (__u32)0xff000000UL) >> 24) )); \
})

#define ___constant_swab32(x) \
        ((__u32)( \
                (((__u32)(x) & (__u32)0x000000ffUL) << 24) | \
                (((__u32)(x) & (__u32)0x0000ff00UL) <<  8) | \
                (((__u32)(x) & (__u32)0x0000ff00UL) <<  8) | \
                (((__u32)(x) & (__u32)0x00ff0000UL) >>  8) | \
                (((__u32)(x) & (__u32)0xff000000UL) >> 24) ))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __le32_to_cpu(x) ((__u32)(x))
#define __cpu_to_le32(x) ((__u32)(x))
#define __be32_to_cpu(x) __swab32((x))
#define __cpu_to_be32(x) __swab32((x))
#define __constant_cpu_to_le32(x) ((__u32)(x))
#define __constant_cpu_to_be32(x) (( __u32)___constant_swab32((x)))
#else
#define __le32_to_cpu(x) __swab32((x))
#define __cpu_to_le32(x) __swab32((x))
#define __be32_to_cpu(x) ((__u32)(x))
#define __cpu_to_be32(x) ((__u32)(x))
#define __constant_cpu_to_le32(x) ___constant_swab32((x))
#define __constant_cpu_to_be32(x) ((__u32)(x))
#endif

#endif /* _LINUX_CRC32_USER_H */
