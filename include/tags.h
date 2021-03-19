#ifndef __TAGS_H__
#define __TAGS_H__

#include <defs.h>
#include <types.h>

#define LZ_TAG_CLASS_MASK	0xF0

/* Tags with no particular class */
#define LZ_TAG_NO_CLASS		0x00
#define LZ_TAG_END		0x00
#define LZ_TAG_UNAWARE_OS	0x01
#define LZ_TAG_TAGS_SIZE	0x0F	/* Always first */

/* Tags specifying kernel type */
#define LZ_TAG_BOOT_CLASS	0x10
#define LZ_TAG_BOOT_LINUX	0x10
#define LZ_TAG_BOOT_MB2		0x11

/* Tags specific to TPM event log */
#define LZ_TAG_EVENT_LOG_CLASS	0x20
#define LZ_TAG_EVENT_LOG	0x20
#define LZ_TAG_LZ_HASH		0x21

struct lz_tag_hdr {
	u8 type;
	u8 len;
} __packed;

struct lz_tag_tags_size {
	struct lz_tag_hdr hdr;
	u16 size;
} __packed;

struct lz_tag_boot_linux {
	struct lz_tag_hdr hdr;
	u32 zero_page;
} __packed;

struct lz_tag_boot_mb2 {
	struct lz_tag_hdr hdr;
	u32 mbi;
	u32 kernel_entry;
	u32 kernel_size;
} __packed;

struct lz_tag_evtlog {
	struct lz_tag_hdr hdr;
	u32 address;
	u32 size;
} __packed;

struct lz_tag_hash {
	struct lz_tag_hdr hdr;
	u16 algo_id;
	u8 digest[];
} __packed;

extern struct lz_tag_tags_size bootloader_data;

static inline void* end_of_tags(void)
{
	return (((void *) &bootloader_data) + bootloader_data.size);
}

static inline void* next_tag(void* t)
{
	void *x = t + ((struct lz_tag_hdr*)t)->len;
	return x < end_of_tags() ? x : NULL;
}

static inline void* next_of_type(void* _t, u8 type)
{
	struct lz_tag_hdr *t = _t;
	while (t->type != LZ_TAG_END) {
		t = next_tag(t);
		if (t->type == type)
			return (void*)t < end_of_tags() ? t : NULL;
	}
	return NULL;
}

static inline void* next_of_class(void* _t, u8 c)
{
	struct lz_tag_hdr *t = _t;
	while (t->type != LZ_TAG_END) {
		t = next_tag(t);
		if ((t->type & LZ_TAG_CLASS_MASK) == c)
			return (void*)t < end_of_tags() ? t : NULL;
	}
	return NULL;
}

#endif /* __TAGS_H__ */
