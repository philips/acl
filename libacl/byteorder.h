#include "config.h"

#ifndef __u16
# if SIZEOF_SHORT == 2
#  define __u16 unsigned short
# elif SIZEOF_INT == 2
#  define __u16 unsigned int
# else
#  error Neither short nor int are 16-bit values.
# endif
#endif

#ifndef __u32
# if SIZEOF_INT == 4
#  define __u32 unsigned int
# elif SIZEOF_LONG == 4
#  define __u32 unsigned long
# else
#  error Neither int nor long are 32-bit values.
# endif
#endif

#ifdef WORDS_BIGENDIAN
# define cpu_to_le16(w16) le16_to_cpu(w16)
# define le16_to_cpu(w16) ((__u16)((__u16)(w16) >> 8) | \
                           (__u16)((__u16)(w16) << 8))
# define cpu_to_le32(w32) le32_to_cpu(w32)
# define le32_to_cpu(w32) ((__u32)( (__u32)(w32) >>24) | \
                           (__u32)(((__u32)(w32) >> 8) & 0xFF00) | \
                           (__u32)(((__u32)(w32) << 8) & 0xFF0000) | \
			   (__u32)( (__u32)(w32) <<24))
#else
# define cpu_to_le16(w16) ((__u16)(w16))
# define le16_to_cpu(w16) ((__u16)(w16))
# define cpu_to_le32(w32) ((__u32)(w32))
# define le32_to_cpu(w32) ((__u32)(w32))
#endif

