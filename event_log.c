/*
 * Copyright (c) 2020 Oracle and/or its affiliates. All rights reserved.
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
#include "tpmlib/tpm.h"
#include "tpmlib/tpm2_constants.h"

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

static int strlen(const char *p)
{
	int count = 0;

	while (*p++) count++;

	return count;
}

#define EV_NO_ACTION    0x3
/* TODO: are these types defined anywhere? */
#define EV_TYPE_SKINIT  0x600
#define EV_TYPE_CODE    0x601

#define HASH_COUNT 2

typedef struct __packed {
	u32 pcr;
	u32 event_type;
	u8  digest[20];
	u32 event_size;
	/* u8 event[]; */
} tpm12_event_t;

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
	/* u8 vendor_info[]; */
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
	/* u8   vendor_info[]; */
} tpm20_spec_id_ev_t;

typedef struct __packed {
	u32 pcr;
	u32 event_type;
	ev_log_hash_t digests;		/* defined in boot.h */
	u32 event_size;
	/* u8 event[]; */
} tpm20_event_t;

static const tpm12_spec_id_ev_t tpm12_id_struct = {
	.c.signature = "Spec ID Event00",
	.c.spec_ver_minor = 2,
	.c.spec_ver_major = 1,
	.c.errata = 1
};

static const tpm20_spec_id_ev_t tpm20_id_struct = {
	.c.signature = "Spec ID Event03",
	.c.spec_ver_minor = 0,
	.c.spec_ver_major = 2,
	.c.errata = 0,
	.c.uintn_size = 2,
	.sizes.number_of_algorithms = HASH_COUNT,
	.sizes.digest_sizes[0].id = TPM_ALG_SHA1,
	.sizes.digest_sizes[0].size = 20,
	.sizes.digest_sizes[1].id = TPM_ALG_SHA256,
	.sizes.digest_sizes[1].size = 32
};

int log_event_tpm12(u32 pcr, u8 sha1[20], char *event)
{
	tpm12_event_t ev;

	ev.pcr = pcr;
	ev.event_type = EV_TYPE_CODE;
	memcpy(ev.digest, sha1, 20);
	ev.event_size = strlen(event);

	if (HAS_ENOUGH_SPACE(sizeof(ev) + ev.event_size)) {
		log_write(&ev, sizeof(ev));
		return log_write(event, ev.event_size);
	}

	return 1;
}

int log_event_tpm20(u32 pcr, u8 sha1[20], u8 sha256[32], char *event)
{
	tpm20_event_t ev;

	ev.pcr = pcr;
	ev.event_type = EV_TYPE_CODE;
	ev.digests.count = 2;
	ev.digests.sha1_id = TPM_ALG_SHA1;
	memcpy(ev.digests.sha1_hash, sha1, 20);
	ev.digests.sha256_id = TPM_ALG_SHA256;
	memcpy(ev.digests.sha256_hash, sha256, 32);
	ev.event_size = strlen(event);

	if (HAS_ENOUGH_SPACE(sizeof(ev) + ev.event_size)) {
		log_write(&ev, sizeof(ev));
		return log_write(event, ev.event_size);
	}

	return 1;
}

/* TODO: make sure stack is big enough */
int event_log_init(struct tpm *tpm)
{
	unsigned int min_size;

	if (lz_header.event_log_addr == 0 || lz_header.event_log_size == 0)
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
	if (lz_header.event_log_size < min_size)
		goto err;

	ptr_current = _p(lz_header.event_log_addr);
	limit = _p(lz_header.event_log_addr + lz_header.event_log_size);

	/* Check for overflow */
	if (ptr_current > limit)
		goto err;

	/*
	 * Bootloader controls location and size, so it could force LZ to overwrite
	 * its code **after** it was measured. Make sure that the Event Log and the
	 * measured part of LZ do not overlap before wiping the memory.
	 */
	if (! ((_p(limit) < _p(_start)) || (_p(&lz_header) < _p(ptr_current))))
		goto err;

	memset(ptr_current, 0, lz_header.event_log_size);

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
		tpm12_event_t ev;

		ev.pcr = 17;
		ev.event_type = EV_TYPE_SKINIT;
		memcpy(&ev.digest, &lz_header.lz_hashes.sha1_hash, 20);
		ev.event_size = 0;

		return log_write(&ev, sizeof(ev));
	} else {
		tpm20_event_t ev;

		ev.pcr = 17;
		ev.event_type = EV_TYPE_SKINIT;
		memcpy(&ev.digests, &lz_header.lz_hashes, sizeof(ev.digests));
		ev.event_size = 0;

		return log_write(&ev, sizeof(ev));
	}

err:
	/* Make sure that further calls to log_write() will fail */
	limit = ptr_current;
	return 1;
}
