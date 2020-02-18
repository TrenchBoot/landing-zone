#ifndef __BYTESWAP_H__
#define __BYTESWAP_H__

/*
 * x86 is little endian.  Conversions to/from big endian all require byte
 * swapping.
 */

#define be16_to_cpu(x) __builtin_bswap16(x)
#define cpu_to_be16(x) __builtin_bswap16(x)

#define be32_to_cpu(x) __builtin_bswap32(x)
#define cpu_to_be32(x) __builtin_bswap32(x)

#define cpu_to_be64(x) __builtin_bswap64(x)
#define be64_to_cpu(x) __builtin_bswap64(x)

#endif /* __BYTESWAP_H__ */
