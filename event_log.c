/*
 * Copyright (C) 2020 3mdeb Embedded Systems Consulting
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <boot.h>
#include <tags.h>
#include "tpmlib/tpm.h"
#include "tpmlib/tpm2_constants.h"

static u8 *evtlog_base;
static u8 *ptr_current;
static u8 *limit;

#define HAS_ENOUGH_SPACE(n)      ((limit - ptr_current) > (n))

static int log_write(const void *data, unsigned size)
{
	if (size >= limit - ptr_current)
		return 1;

	memcpy(ptr_current, data, size);
	ptr_current += size;
	return 0;
}

#define EV_NO_ACTION    0x3
#define EV_TYPE_SLAUNCH 0x502

#define HASH_COUNT 2

/* For compatibility with TXT and easier operations */

#define TPM12_EVTLOG_SIGNATURE "TXT Event Container"

typedef struct __packed {
	char signature[20];
	char reserved[12];
	u8 container_ver_major;
	u8 container_ver_minor;
	u8 pcr_event_ver_major;
	u8 pcr_event_ver_minor;
	u32 container_size;
	u32 pcr_events_offset;
	u32 next_event_offset;
	/* PCREvents[] */
} tpm12_event_log_header;

typedef struct __packed {
	u64 phys_addr;
	u32 allocated_event_container_size;
	u32 first_record_offset;
	u32 next_record_offset;
} txt_event_log_pointer2_1_element;

/* Event log headers */

typedef struct __packed {
	char signature[16];
	u32  platform_class;
	u8   spec_ver_minor;
	u8   spec_ver_major;
	u8   errata;
	u8   uintn_size;		/* reserved (must be 0) for 1.21 */
} common_spec_id_ev_t;

typedef struct __packed {
	common_spec_id_ev_t c;
	u8   vendor_info_size;
	tpm12_event_log_header hdr;				/* AKA u8 vendor_info[]; */
} tpm12_spec_id_ev_t;

typedef struct __packed {
	u32  number_of_algorithms;
	/* Hardcode table size so we can use sizeof */
	struct {
		u16  id;
		u16  size;
	} digest_sizes[HASH_COUNT];
} tpm20_digest_sizes_t;

typedef struct __packed {
	common_spec_id_ev_t c;
	tpm20_digest_sizes_t sizes;
	u8   vendor_info_size;
	txt_event_log_pointer2_1_element el;	/* AKA u8 vendor_info[]; */
} tpm20_spec_id_ev_t;

/* Event log entries */

typedef struct __packed {
	u32 pcr;
	u32 event_type;
	u8  digest[20];
	u32 event_size;
	/* u8 event[]; */
} tpm12_event_t;

typedef struct __packed {
	u32 pcr;
	u32 event_type;
	ev_log_hash_t digests;		/* defined in boot.h */
	u32 event_size;
	/* u8 event[]; */
} tpm20_event_t;

static tpm12_spec_id_ev_t tpm12_id_struct = {
	.c.signature = "Spec ID Event00",
	.c.spec_ver_minor = 2,
	.c.spec_ver_major = 1,
	.c.errata = 1,
	.vendor_info_size = sizeof(tpm12_event_log_header),
	.hdr.signature = TPM12_EVTLOG_SIGNATURE,
	.hdr.container_ver_major = 1,
	.hdr.container_ver_minor = 0,
	.hdr.pcr_event_ver_major = 1,
	.hdr.pcr_event_ver_minor = 0,
	/*
	 * HACK: this offset should be relative to the base of Event Log, but TXT
	 * creates its log starting with the .hdr.signature, not .c.signature.
	 * Linux kernel sets its evtlog_base to the address of the former one in
	 * order to use the same code for both of the supported CPU vendors.
	 */
	.hdr.pcr_events_offset = sizeof(tpm12_event_log_header),
	.hdr.next_event_offset = sizeof(tpm12_event_log_header)
};

static tpm20_spec_id_ev_t tpm20_id_struct = {
	.c.signature = "Spec ID Event03",
	.c.spec_ver_minor = 0,
	.c.spec_ver_major = 2,
	.c.errata = 0,
	.c.uintn_size = 2,
	.sizes.number_of_algorithms = HASH_COUNT,
	.sizes.digest_sizes[0].id = TPM_ALG_SHA1,
	.sizes.digest_sizes[0].size = 20,
	.sizes.digest_sizes[1].id = TPM_ALG_SHA256,
	.sizes.digest_sizes[1].size = 32,
	.vendor_info_size = sizeof(txt_event_log_pointer2_1_element),
	.el.first_record_offset = sizeof(tpm20_spec_id_ev_t) + sizeof(tpm12_event_t),
	.el.next_record_offset = sizeof(tpm20_spec_id_ev_t) + sizeof(tpm12_event_t)
};

int log_event_tpm12(u32 pcr, u8 sha1[20], char *event)
{
	tpm12_event_t ev;
	tpm12_spec_id_ev_t *base = (tpm12_spec_id_ev_t *)
								(evtlog_base + sizeof(tpm12_event_t));

	ev.event_size = strlen(event);

	if (HAS_ENOUGH_SPACE(sizeof(ev) + ev.event_size)) {
		ev.pcr = pcr;
		ev.event_type = EV_TYPE_SLAUNCH;
		memcpy(ev.digest, sha1, 20);
		base->hdr.next_event_offset += sizeof(ev) + ev.event_size;
		log_write(&ev, sizeof(ev));
		return log_write(event, ev.event_size);
	}

	return 1;
}

int log_event_tpm20(u32 pcr, u8 sha1[20], u8 sha256[32], char *event)
{
	tpm20_event_t ev;
	tpm20_spec_id_ev_t *base = (tpm20_spec_id_ev_t *)
								(evtlog_base + sizeof(tpm12_event_t));

	ev.event_size = strlen(event);

	if (HAS_ENOUGH_SPACE(sizeof(ev) + ev.event_size)) {
		ev.pcr = pcr;
		ev.event_type = EV_TYPE_SLAUNCH;
		ev.digests.count = 2;
		ev.digests.sha1_id = TPM_ALG_SHA1;
		memcpy(ev.digests.sha1_hash, sha1, 20);
		ev.digests.sha256_id = TPM_ALG_SHA256;
		memcpy(ev.digests.sha256_hash, sha256, 32);
		base->el.next_record_offset += sizeof(ev) + ev.event_size;
		log_write(&ev, sizeof(ev));
		return log_write(event, ev.event_size);
	}

	return 1;
}

int event_log_init(struct tpm *tpm)
{
	unsigned int min_size;
	struct lz_tag_evtlog *t = next_of_type(&bootloader_data, LZ_TAG_EVENT_LOG);

	if (t == NULL || next_of_type(t, LZ_TAG_EVENT_LOG) != NULL)
		goto err;

	min_size = sizeof (tpm12_event_t);

	if (tpm->family == TPM12) {
		min_size += sizeof(tpm12_id_struct);
		min_size += 2 * sizeof(tpm12_event_t); /* LZ and kernel hashes */
	} else if (tpm->family == TPM20) {
		min_size += sizeof(tpm20_id_struct);
		min_size += 2 * sizeof(tpm20_event_t); /* LZ and kernel hashes */
	} else {
		goto err;
	}

	/* Note that min_size does not include tpmXX_event_t.event[] entries */
	if (t->size < min_size)
		goto err;

	ptr_current = evtlog_base = _p(t->address);
	limit = _p(t->address + t->size);

	/* Check for overflow */
	if (ptr_current > limit)
		goto err;

	/*
	 * Bootloader controls location and size, so it could force LZ to overwrite
	 * its code **after** it was measured. Make sure that the Event Log and LZ
	 * do not overlap before wiping the memory.
	 */
	if (!(_p(limit) < _p(_start) || _p(_start + SLB_SIZE) < _p(ptr_current)))
		goto err;

	tpm12_id_struct.hdr.container_size =
			tpm20_id_struct.el.allocated_event_container_size =
			t->size;
	tpm20_id_struct.el.phys_addr = _u(evtlog_base);

	memset(ptr_current, 0, t->size);

	/* Write log header */
	{
		tpm12_event_t ev;

		ev.pcr = 0;
		ev.event_type = EV_NO_ACTION;
		memset(ev.digest, 0, 20);
		if (tpm->family == TPM12) {
			ev.event_size = sizeof(tpm12_id_struct);
		} else {
			ev.event_size = sizeof(tpm20_id_struct);
		}

		log_write(&ev, sizeof(ev));
	}

	if (tpm->family == TPM12) {
		log_write(&tpm12_id_struct, sizeof(tpm12_id_struct));
	} else {
		log_write(&tpm20_id_struct, sizeof(tpm20_id_struct));
	}

	/* Log what was done by SKINIT */
	if (tpm->family == TPM12) {
		struct lz_tag_hash *h = next_of_type(&bootloader_data, LZ_TAG_LZ_HASH);

		while (h != NULL) {
			if (h->algo_id == TPM_ALG_SHA1)
				return log_event_tpm12(17, h->digest, "SKINIT");

			h = next_of_type(h, LZ_TAG_LZ_HASH);
		}

		/* No SHA1 hash was passed by a bootloader? */
		return 1;
	} else {
		struct lz_tag_hash *h = next_of_type(&bootloader_data, LZ_TAG_LZ_HASH);
		u8 *sha1 = NULL;
		u8 *sha256 = NULL;

		while (h != NULL) {
			if (h->algo_id == TPM_ALG_SHA1)
				sha1 = h->digest;

			if (h->algo_id == TPM_ALG_SHA256)
				sha256 = h->digest;

			if (sha1 != NULL && sha256 != NULL)
				return log_event_tpm20(17, sha1, sha256, "SKINIT");

			h = next_of_type(h, LZ_TAG_LZ_HASH);
		}

		/* Either SHA1 or SHA256 hash wasn't passed by a bootloader? */
		return 1;
	}

err:
	/* Make sure that further calls to log_write() will fail */
	limit = ptr_current;
	return 1;
}
