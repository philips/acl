#define SIZEOF_SHORT 2
#define SIZEOF_INT   4
#define SIZEOF_LONG  4
#define WORDS_BIGENDIAN
#include "byteorder.h"

__u16 swap16(__u16 u16) {
	return cpu_to_le16(u16);
}

__u32 swap32(__u32 u32) {
	return cpu_to_le32(u32);
}

int main(void)
{
        __u16 u16 = 0xFADE;
        __u32 u32 = 0xDEADBEEF;

        printf("0x%X 0x%X\n", u16, u32);
        u16 = swap16(u16);
        u32 = swap32(u32);
        printf("0x%X 0x%X\n", u16, u32);
}

