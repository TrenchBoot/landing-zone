/*
 * Copyright (c) 2018 Daniel P. Smith, Apertus Solutions, LLC
 *
 * The definitions in this header are extracted from:
 *  - Trusted Computing Group's "TPM Main Specification", Parts 1-3.
 *  - Trusted Computing Group's TPM 2.0 Library Specification Parts 1&2.
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
 *
 */

#include <types.h>
#include <boot.h>
#include <byteswap.h>
#include <errno-base.h>
#include <tpm.h>

#include "early_tpm.h"

static u8 locality = TPM_NO_LOCALITY;

/*** tpm_buff.c ***/


#define STATIC_TIS_BUFFER_SIZE		1024

#define TPM_CRB_DATA_BUFFER_OFFSET	0x80
#define TPM_CRB_DATA_BUFFER_SIZE	3966

u8 *tpmb_reserve(struct tpmbuff *b)
{
	if (b->locked)
		return NULL;

	b->len = sizeof(struct tpm_header);
	b->locked = 1;
	b->data = b->head + b->len;
	b->tail = b->data;

	return b->head;
}

void tpmb_free(struct tpmbuff *b)
{
	memset(b->head, 0, b->len);

	b->len = 0;
	b->locked = 0;
	b->data = NULL;
	b->tail = NULL;
}

u8 *tpmb_put(struct tpmbuff *b, size_t size)
{
	u8 *tail = b->tail;

	if ((b->len + size) > b->truesize)
		return NULL; /* TODO: add overflow buffer support */

	b->tail += size;
	b->len += size;

	return tail;
}

size_t tpmb_trim(struct tpmbuff *b, size_t size)
{
	if (b->len < size)
		size = b->len;

	/* TODO: add overflow buffer support */

	b->tail -= size;
	b->len -= size;

	return size;
}

size_t tpmb_size(struct tpmbuff *b)
{
	return b->len;
}

static u8 tis_buff[STATIC_TIS_BUFFER_SIZE];
static struct tpmbuff tpm_buff;

struct tpmbuff *alloc_tpmbuff(enum tpm_hw_intf intf, u8 l)
{
	struct tpmbuff *b = &tpm_buff;

	switch (intf) {
	case TPM_DEVNODE:
		/* TODO: need implementation */
		goto err;
	case TPM_TIS:
		if (b->head)
			goto reset;

		b->head = (u8 *)&tis_buff;
		b->truesize = STATIC_TIS_BUFFER_SIZE;
		break;
	case TPM_CRB:
		b->head = _p(TPM_MMIO_BASE + (l << 12)
			       + TPM_CRB_DATA_BUFFER_OFFSET);
		b->truesize = TPM_CRB_DATA_BUFFER_SIZE;
		break;
	case TPM_UEFI:
		/* Not implemented yet */
		goto err;
	default:
		goto err;
	}

reset:
	b->len = 0;
	b->locked = 0;
	b->data = NULL;
	b->tail = NULL;
	b->end = b->head + (b->truesize - 1);

	return b;

err:
	return NULL;
}

void free_tpmbuff(struct tpmbuff *b, enum tpm_hw_intf intf)
{
	switch (intf) {
	case TPM_DEVNODE:
		/* Not implemented yet */
		break;
	case TPM_TIS:
		b->head = NULL;
		break;
	case TPM_CRB:
		b->head = NULL;
		break;
	case TPM_UEFI:
		/* Not implemented yet */
		break;
	default:
		break;
	}
}

/*** tpmio.c ***/

static void tpm_io_delay(void)
{
	io_delay();
}

static void tpm_udelay(int loops)
{
	while (loops--)
		tpm_io_delay();	/* Approximately 1 us */
}

void tpm_mdelay(int ms)
{
	int i;

	for (i = 0; i < ms; i++)
		tpm_udelay(1000);
}

u8 tpm_read8(u32 field)
{
	return ioread8(_p(TPM_MMIO_BASE | field));
}

void tpm_write8(unsigned char val, u32 field)
{
	iowrite8(_p(TPM_MMIO_BASE | field), val);
}

u32 tpm_read32(u32 field)
{
	return ioread32(_p(TPM_MMIO_BASE | field));
}

void tpm_write32(u32 val, u32 field)
{
	iowrite32(_p(TPM_MMIO_BASE | field), val);
}

/*** tis.c ***/


#define TPM_BURST_MIN_DELAY 100 /* 100us */


static u32 burst_wait(void)
{
	u32 count = 0;

	while (count == 0) {
		count = tpm_read8(STS(locality) + 1);
		count += tpm_read8(STS(locality) + 2) << 8;

		/* Wait for FIFO to drain */
		if (count == 0)
			tpm_udelay(TPM_BURST_MIN_DELAY);
	}

	return count;
}

void tis_relinquish_locality(void)
{
	if (locality < TPM_MAX_LOCALITY)
		tpm_write8(ACCESS_RELINQUISH_LOCALITY, ACCESS(locality));

	locality = TPM_NO_LOCALITY;
}

u8 tis_request_locality(u8 l)
{
	if (l > TPM_MAX_LOCALITY)
		return TPM_NO_LOCALITY;

	if (l == locality)
		return locality;

	tis_relinquish_locality();

	tpm_write8(ACCESS_REQUEST_USE, ACCESS(l));

	/* wait for locality to be granted */
	if (tpm_read8(ACCESS(l)) & ACCESS_ACTIVE_LOCALITY)
		locality = l;

	return locality;
}

u8 tis_init(struct tpm *t)
{
	locality = TPM_NO_LOCALITY;

	if (tis_request_locality(0) != 0)
		return 0;

	t->vendor = tpm_read32(DID_VID(0));
	if ((t->vendor & 0xFFFF) == 0xFFFF)
		return 0;

	return 1;
}

size_t tis_send(struct tpmbuff *buf)
{
	u8 status, *buf_ptr;
	u32 burstcnt = 0;
	u32 count = 0;

	if (locality > TPM_MAX_LOCALITY)
		return 0;

	for (status = 0; (status & STS_COMMAND_READY) == 0; ) {
		tpm_write8(STS_COMMAND_READY, STS(locality));
		status = tpm_read8(STS(locality));
	}

	buf_ptr = buf->head;

	/* send all but the last byte */
	while (count < (buf->len - 1)) {
		burstcnt = burst_wait();
		for (; burstcnt > 0 && count < (buf->len - 1); burstcnt--) {
			tpm_write8(buf_ptr[count], DATA_FIFO(locality));
			count++;
		}

		/* check for overflow */
		for (status = 0; (status & STS_VALID) == 0; )
			status = tpm_read8(STS(locality));

		if ((status & STS_DATA_EXPECT) == 0)
			return 0;
	}

	/* write last byte */
	tpm_write8(buf_ptr[buf->len - 1], DATA_FIFO(locality));
	count++;

	/* make sure it stuck */
	for (status = 0; (status & STS_VALID) == 0; )
		status = tpm_read8(STS(locality));

	if ((status & STS_DATA_EXPECT) != 0)
		return 0;

	/* go and do it */
	tpm_write8(STS_GO, STS(locality));

	return (size_t)count;
}

static size_t recv_data(unsigned char *buf, size_t len)
{
	size_t size = 0;
	u8 *bufptr;
	u32 burstcnt = 0;

	bufptr = (u8 *)buf;

	while (tis_data_available(locality) && size < len) {
		burstcnt = burst_wait();
		for (; burstcnt > 0 && size < len; burstcnt--) {
			*bufptr = tpm_read8(DATA_FIFO(locality));
			bufptr++;
			size++;
		}
	}

	return size;
}

size_t tis_recv(enum tpm_family f, struct tpmbuff *buf)
{
	u32 expected;
	u8 *buf_ptr;
	struct tpm_header *hdr;

	if (locality > TPM_MAX_LOCALITY)
		goto err;

	/* ensure that there is data available */
	if (!tis_data_available(locality)) {
		if (f == TPM12)
			tpm1_timeout_d();
		else
			tpm2_timeout_d();

		if (!tis_data_available(locality))
			goto err;
	}

	/* read header */
	hdr = (struct tpm_header *)buf->head;
	expected = sizeof(struct tpm_header);
	if (recv_data(buf->head, expected) < expected)
		goto err;

	/* convert header */
	hdr->tag = be16_to_cpu(hdr->tag);
	hdr->size = be32_to_cpu(hdr->size);
	hdr->code = be32_to_cpu(hdr->code);

	/* protect against integer underflow */
	if (hdr->size <= expected)
		goto err;

	/* hdr->size = header + data */
	expected = hdr->size - expected;
	buf_ptr = tpmb_put(buf, expected);
	if (!buf_ptr)
		goto err;

	/* read all data, except last byte */
	if (recv_data(buf_ptr, expected - 1) < (expected - 1))
		goto err;

	/* check for receive underflow */
	if (!tis_data_available(locality))
		goto err;

	/* read last byte */
	if (recv_data(buf_ptr, 1) != 1)
		goto err;

	/* make sure we read everything */
	if (tis_data_available(locality))
		goto err;

	tpm_write8(STS_COMMAND_READY, STS(locality));

	return hdr->size;
err:
	return 0;
}

/*** crb.c ***/


#define TPM_LOC_STATE		0x0000
#define TPM_LOC_CTRL		0x0008
#define TPM_LOC_STS		0x000C
#define TPM_CRB_INTF_ID		0x0030
#define TPM_CRB_CTRL_EXT	0x0038
#define TPM_CRB_CTRL_REQ	0x0040
#define TPM_CRB_CTRL_STS	0x0044
#define TPM_CRB_CTRL_CANCEL	0x0048
#define TPM_CRB_CTRL_START	0x004C
#define TPM_CRB_INT_ENABLE	0x0050
#define TPM_CRB_INT_STS		0x0054
#define TPM_CRB_CTRL_CMD_SIZE	0x0058
#define TPM_CRB_CTRL_CMD_LADDR	0x005C
#define TPM_CRB_CTRL_CMD_HADDR	0x0060
#define TPM_CRB_CTRL_RSP_SIZE	0x0064
#define TPM_CRB_CTRL_RSP_ADDR	0x0068
#define TPM_CRB_DATA_BUFFER	0x0080

#define REGISTER(l, r)		(((l) << 12) | (r))


struct tpm_loc_state {
	union {
		u8 val;
		struct {
			u8 tpm_established:1;
			u8 loc_assigned:1;
			u8 active_locality:3;
			u8 _reserved:2;
			u8 tpm_reg_valid_sts:1;
		};
	};
} __attribute__ ((packed));

struct tpm_loc_ctrl {
	union {
		u32 val;
		struct {
			u32 request_access:1;
			u32 relinquish:1;
			u32 seize:1;
			u32 reset_establishment_bit:1;
			u32 _reserved:28;
		};
	};
} __attribute__ ((packed));

struct tpm_loc_sts {
	union {
		u32 val;
		struct {
			u32 granted:1;
			u32 beenSeized:1;
			u32 _reserved:30;
		};
	};
} __attribute__ ((packed));

struct tpm_crb_ctrl_req {
	union {
		u32 val;
		struct {
			u32 cmd_ready:1;
			u32 go_idle:1;
			u32 _reserved:30;
		};
	};
} __attribute__ ((packed));

struct tpm_crb_ctrl_sts {
	union {
		u32 val;
		struct {
			u32 tpm_sts:1;
			u32 tpm_idle:1;
			u32 _reserved:30;
		};
	};
} __attribute__ ((packed));

struct tpm_crb_intf_id_ext {
	union {
		u32 val;
		struct {
			u32 vid:16;
			u32 did:16;
		};
	};
} __attribute__ ((packed));

static u8 is_idle(void)
{
	struct tpm_crb_ctrl_sts ctl_sts;

	ctl_sts.val = tpm_read32(REGISTER(locality, TPM_CRB_CTRL_STS));
	if (ctl_sts.tpm_idle == 1)
		return 1;

	return 0;
}

static inline u8 is_ready(void)
{
	struct tpm_crb_ctrl_sts ctl_sts;

	ctl_sts.val = tpm_read32(REGISTER(locality, TPM_CRB_CTRL_STS));
	return ctl_sts.val == 0;
}

static u8 is_cmd_exec(void)
{
	u32 ctrl_start;

	ctrl_start = tpm_read32(REGISTER(locality, TPM_CRB_CTRL_START));
	if (ctrl_start == 1)
		return 1;

	return 0;
}

static u8 cmd_ready(void)
{
	struct tpm_crb_ctrl_req ctl_req;

	if (is_idle()) {
		ctl_req.cmd_ready = 1;
		tpm_write32(ctl_req.val, REGISTER(locality, TPM_CRB_CTRL_REQ));
		tpm2_timeout_c();

		if (is_idle())
			return -1;
	}

	return 0;
}

static void go_idle(void)
{
	struct tpm_crb_ctrl_req ctl_req;

	if (is_idle())
		return;

	ctl_req.go_idle = 1;
	tpm_write32(ctl_req.val, REGISTER(locality, TPM_CRB_CTRL_REQ));

	/* pause to give tpm time to complete the request */
	tpm2_timeout_c();
}

static void crb_relinquish_locality_internal(u16 l)
{
	struct tpm_loc_ctrl loc_ctrl;

	loc_ctrl.relinquish = 1;

	tpm_write32(loc_ctrl.val, REGISTER(l, TPM_LOC_CTRL));
}

u8 crb_request_locality(u8 l)
{
	struct tpm_loc_state loc_state;
	struct tpm_loc_ctrl loc_ctrl;
	struct tpm_loc_sts loc_sts;

	/* TPM_LOC_STATE is aliased across all localities */
	loc_state.val = tpm_read8(REGISTER(0, TPM_LOC_STATE));

	if (loc_state.loc_assigned == 1) {
		if (loc_state.active_locality == l) {
			locality = l;
			return locality;
		}

		crb_relinquish_locality_internal(loc_state.loc_assigned);
	}

	loc_ctrl.request_access = 1;
	tpm_write32(loc_ctrl.val, REGISTER(l, TPM_LOC_CTRL));

	loc_sts.val = tpm_read32(REGISTER(l, TPM_LOC_STS));
	if (loc_sts.granted != 1) {
		locality = TPM_NO_LOCALITY;
		return locality;
	}

	locality = l;
	return locality;
}

void crb_relinquish_locality(void)
{
	crb_relinquish_locality_internal(locality);
}

u8 crb_init(struct tpm *t)
{
	u8 i;
	struct tpm_crb_intf_id_ext id;

	for (i = 0; i <= TPM_MAX_LOCALITY; i++)
		crb_relinquish_locality_internal(i);

	if (crb_request_locality(0) == TPM_NO_LOCALITY)
		return 0;

	id.val = tpm_read32(REGISTER(0, TPM_CRB_INTF_ID + 4));
	t->vendor = ((id.vid & 0x00FF) << 8) | ((id.vid & 0xFF00) >> 8);
	if ((t->vendor & 0xFFFF) == 0xFFFF)
		return 0;

	/* have the tpm invalidate the buffer if left in completion state */
	go_idle();
	/* now move to ready state */
	cmd_ready();

	return 1;
}

/* assumes cancel will succeed */
static void cancel_send(void)
{
	if (is_cmd_exec()) {
		tpm_write32(1, REGISTER(locality, TPM_CRB_CTRL_CANCEL));
		timeout_b();

		tpm_write32(0, REGISTER(locality, TPM_CRB_CTRL_CANCEL));
	}
}

size_t crb_send(struct tpmbuff *buf)
{
	u32 ctrl_start = 1;

	if (is_idle())
		return 0;

	tpm_write32(ctrl_start, REGISTER(locality, TPM_CRB_CTRL_START));

	/*
	 * Most command sequences this code is interested with operates with
	 * 20/750 duration/timeout schedule
	 */
	duration_a();
	ctrl_start = tpm_read32(REGISTER(locality, TPM_CRB_CTRL_START));
	if (ctrl_start != 0) {
		timeout_a();
		ctrl_start = tpm_read32(REGISTER(locality, TPM_CRB_CTRL_START));
		if (ctrl_start != 0) {
			cancel_send();
			/* minimum response is header with cancel ord */
			return sizeof(struct tpm_header);
		}
	}

	return buf->len;
}

size_t crb_recv(struct tpmbuff *buf)
{
	/* noop, currently send waits until execution is complete*/
	return 0;
}

/*** tpm1_cmds.c ***/


int tpm1_pcr_extend(struct tpm *t, struct tpm_digest *d)
{
	int ret = 0;
	struct tpmbuff *b = t->buff;
	struct tpm_header *hdr;
	struct tpm_extend_cmd *cmd;
	size_t size;

	if (b == NULL) {
		ret = -EINVAL;
		goto out;
	}

	if (!tpmb_reserve(b)) {
		ret = -ENOMEM;
		goto out;
	}

	hdr = (struct tpm_header *)b->head;

	hdr->tag = cpu_to_be16(TPM_TAG_RQU_COMMAND);
	hdr->code = cpu_to_be32(TPM_ORD_EXTEND);

	cmd = (struct tpm_extend_cmd *)
		tpmb_put(b, sizeof(struct tpm_extend_cmd));
	if (cmd == NULL) {
		ret = -ENOMEM;
		goto free;
	}

	cmd->pcr_num = cpu_to_be32(d->pcr);
	memcpy(&(cmd->digest), &(d->digest), sizeof(TPM_DIGEST));

	hdr->size = cpu_to_be32(tpmb_size(b));

	switch (t->intf) {
	case TPM_DEVNODE:
		/* Not implemented yet */
		ret = -EBADRQC;
		break;
	case TPM_TIS:
		if (be32_to_cpu(hdr->size) != tis_send(b))
			ret = -EAGAIN;
		break;
	case TPM_CRB:
		/* Not valid for TPM 1.2 */
		ret = -ENODEV;
		break;
	case TPM_UEFI:
		/* Not implemented yet */
		ret = -EBADRQC;
		break;
	}

	if (ret)
		goto free;

	tpmb_free(b);

	/* Reset buffer for receive */
	if (!tpmb_reserve(b)) {
		ret = -ENOMEM;
		goto out;
	}

	hdr = (struct tpm_header *)b->head;

	/*
	 * The extend receive operation returns a struct tpm_extend_resp
	 * but the current implementation ignores the returned PCR value.
	 */

	switch (t->intf) {
	case TPM_DEVNODE:
		/* Not implemented yet */
		ret = -EBADRQC;
		break;
	case TPM_TIS:
		/* tis_recv() will increase the buffer size */
		size = tis_recv(t->family, b);
		if (tpmb_size(b) != size)
			ret = -EAGAIN;
		break;
	case TPM_CRB:
		/* Not valid for TPM 1.2 */
		ret = -ENODEV;
		break;
	case TPM_UEFI:
		/* Not implemented yet */
		ret = -EBADRQC;
		break;
	}

	tpmb_free(b);

	if (ret)
		goto out;

	/*
	 * On return, the code field is used for the return code out. Though
	 * the commands specifications section 16.1 implies there is an
	 * ordinal field, the return size and values point to this being
	 * incorrect.
	 *
	 * Also tis_recv() converts the header back to CPU endianness.
	 */
	if (hdr->code != TPM_SUCCESS)
		ret = -EAGAIN;

	return ret;
free:
	tpmb_free(b);
out:
	return ret;
}

/*** tpm2_auth.c ***/


#define NULL_AUTH_SIZE 9

u32 tpm2_null_auth_size(void)
{
	return NULL_AUTH_SIZE;
}

u8 *tpm2_null_auth(struct tpmbuff *b)
{
	u32 *handle;
	u8 *auth = (u8 *)tpmb_put(b, NULL_AUTH_SIZE);
	if (auth == NULL)
		goto out;

	memset(auth, 0, NULL_AUTH_SIZE);

	/*
	 * The handle, the first element, is the
	 * only non-zero value in a NULL auth
	 */
	handle = (u32 *)auth;
	*handle = cpu_to_be32(TPM_RS_PW);

out:
	return auth;
}

/*** tpm2_cmds.c ***/


static int tpm2_alloc_cmd(struct tpmbuff *b, struct tpm2_cmd *c, u16 tag,
		u32 code)
{
	c->header = (struct tpm_header *)tpmb_reserve(b);
	if (!c->header)
		return -ENOMEM;

	c->header->tag = cpu_to_be16(tag);
	c->header->code = cpu_to_be32(code);

	return 0;
}

static u16 convert_digest_list(struct tpml_digest_values *digests)
{
	int i;
	u16 size = sizeof(digests->count);
	struct tpmt_ha *h = digests->digests;

	for (i = 0; i < digests->count; i++) {
		switch (h->alg) {
		case TPM_ALG_SHA1:
			h->alg = cpu_to_be16(h->alg);
			h = (struct tpmt_ha *)((u8 *)h + SHA1_SIZE);
			size += sizeof(u16) + SHA1_SIZE;
			break;
		case TPM_ALG_SHA256:
			h->alg = cpu_to_be16(h->alg);
			h = (struct tpmt_ha *)((u8 *)h + SHA256_SIZE);
			size += sizeof(u16) + SHA256_SIZE;
			break;
		case TPM_ALG_SHA384:
			h->alg = cpu_to_be16(h->alg);
			h = (struct tpmt_ha *)((u8 *)h + SHA384_SIZE);
			size += sizeof(u16) + SHA384_SIZE;
			break;
		case TPM_ALG_SHA512:
			h->alg = cpu_to_be16(h->alg);
			h = (struct tpmt_ha *)((u8 *)h + SHA512_SIZE);
			size += sizeof(u16) + SHA512_SIZE;
			break;
		case TPM_ALG_SM3_256:
			h->alg = cpu_to_be16(h->alg);
			h = (struct tpmt_ha *)((u8 *)h + SM3256_SIZE);
			size += sizeof(u16) + SHA1_SIZE;
			break;
		default:
			return 0;
		}
	}

	digests->count = cpu_to_be32(digests->count);

	return size;
}

int tpm2_extend_pcr(struct tpm *t, u32 pcr,
		struct tpml_digest_values *digests)
{
	struct tpmbuff *b = t->buff;
	struct tpm2_cmd cmd;
	u16 size;
	int ret = 0;

	if (b == NULL) {
		ret = -EINVAL;
		goto out;
	}

	ret = tpm2_alloc_cmd(b, &cmd, TPM_ST_SESSIONS, TPM_CC_PCR_EXTEND);
	if (ret < 0)
		goto out;

	cmd.handles = (u32 *)tpmb_put(b, sizeof(u32));
	if (cmd.handles == NULL) {
		ret = -ENOMEM;
		goto free;
	}

	cmd.handles[0] = cpu_to_be32(pcr);

	cmd.auth_size = (u32 *)tpmb_put(b, sizeof(u32));
	if (cmd.auth_size == NULL) {
		ret = -ENOMEM;
		goto free;
	}

	cmd.auth = tpm2_null_auth(b);
	if (cmd.auth == NULL) {
		ret = -ENOMEM;
		goto free;
	}

	*cmd.auth_size = cpu_to_be32(tpm2_null_auth_size());

	size = convert_digest_list(digests);
	if (size == 0) {
		ret = -ENOMEM;
		goto free;
	}

	cmd.params = (u8 *)tpmb_put(b, size);
	if (cmd.params == NULL) {
		ret = -ENOMEM;
		goto free;
	}

	memcpy(cmd.params, digests, size);

	cmd.header->size = cpu_to_be32(tpmb_size(b));

	switch (t->intf) {
	case TPM_DEVNODE:
		/* Not implemented yet */
		ret = -EBADRQC;
		break;
	case TPM_TIS:
		size = tis_send(b);
		if (tpmb_size(b) != size)
			ret = -EAGAIN;
		break;
	case TPM_CRB:
		size = crb_send(b);
		if (tpmb_size(b) != size)
			ret = -EAGAIN;
		break;
	case TPM_UEFI:
		/* Not implemented yet */
		ret = -EBADRQC;
		break;
	}

free:
	tpmb_free(b);
out:
	return ret;
}

/*** tpm.c ***/


static struct tpm tpm;

static void find_interface_and_family(struct tpm *t)
{
	struct tpm_interface_id intf_id;
	struct tpm_intf_capability intf_cap;

	/* Sort out whether if it is 1.2 */
	intf_cap.val = tpm_read32(TPM_INTF_CAPABILITY_0);
	if ((intf_cap.interface_version == TPM12_TIS_INTF_12) ||
	    (intf_cap.interface_version == TPM12_TIS_INTF_13)) {
		t->family = TPM12;
		t->intf = TPM_TIS;
		return;
	}

	/* Assume that it is 2.0 and TIS */
	t->family = TPM20;
	t->intf = TPM_TIS;

	/* Check if the interface is CRB */
	intf_id.val = tpm_read32(TPM_INTERFACE_ID_0);
	if (intf_id.interface_type == TPM_CRB_INTF_ACTIVE)
		t->intf = TPM_CRB;
}

struct tpm *enable_tpm(void)
{
	struct tpm *t = &tpm;

	find_interface_and_family(t);

	switch (t->intf) {
	case TPM_DEVNODE:
		/* Not implemented yet */
		break;
	case TPM_TIS:
		if (!tis_init(t))
			goto err;
		break;
	case TPM_CRB:
		if (!crb_init(t))
			goto err;
		break;
	case TPM_UEFI:
		/* Not implemented yet */
		break;
	}

	/* TODO: ACPI TPM discovery */

	return t;

err:
	return NULL;
}

u8 tpm_request_locality(struct tpm *t, u8 l)
{
	u8 ret = TPM_NO_LOCALITY;

	switch (t->intf) {
	case TPM_DEVNODE:
		/* Not implemented yet */
		break;
	case TPM_TIS:
		ret = tis_request_locality(l);
		break;
	case TPM_CRB:
		ret = crb_request_locality(l);
		break;
	case TPM_UEFI:
		/* Not implemented yet */
		break;
	}

	if (ret < TPM_MAX_LOCALITY)
		t->buff = alloc_tpmbuff(t->intf, ret);

	return ret;
}

void tpm_relinquish_locality(struct tpm *t)
{
	switch (t->intf) {
	case TPM_DEVNODE:
		/* Not implemented yet */
		break;
	case TPM_TIS:
		tis_relinquish_locality();
		break;
	case TPM_CRB:
		crb_relinquish_locality();
		break;
	case TPM_UEFI:
		/* Not implemented yet */
		break;
	}

	free_tpmbuff(t->buff, t->intf);
}

#define MAX_TPM_EXTEND_SIZE 70 /* TPM2 SHA512 is the largest */
int tpm_extend_pcr(struct tpm *t, u32 pcr, u16 algo,
		u8 *digest)
{
	int ret = 0;

	if (t->buff == NULL) {
		ret = -EINVAL;
		goto out;
	}

	if (t->family == TPM12) {
		struct tpm_digest d;

		if (algo != TPM_ALG_SHA1) {
			ret = -EINVAL;
			goto out;
		}

		d.pcr = pcr;
		memcpy((void *)d.digest.sha1.digest,
			digest, SHA1_DIGEST_SIZE);

		ret = tpm1_pcr_extend(t, &d);
	} else if (t->family == TPM20) {
		struct tpml_digest_values *d;
		u8 buf[MAX_TPM_EXTEND_SIZE];

		d = (struct tpml_digest_values *) buf;
		d->count = 1;
		switch (algo) {
		case TPM_ALG_SHA1:
			d->digests->alg = TPM_ALG_SHA1;
			memcpy(d->digests->digest, digest, SHA1_SIZE);
			break;
		case TPM_ALG_SHA256:
			d->digests->alg = TPM_ALG_SHA256;
			memcpy(d->digests->digest, digest, SHA256_SIZE);
			break;
		case TPM_ALG_SHA384:
			d->digests->alg = TPM_ALG_SHA384;
			memcpy(d->digests->digest, digest, SHA384_SIZE);
			break;
		case TPM_ALG_SHA512:
			d->digests->alg = TPM_ALG_SHA512;
			memcpy(d->digests->digest, digest, SHA512_SIZE);
			break;
		case TPM_ALG_SM3_256:
			d->digests->alg = TPM_ALG_SM3_256;
			memcpy(d->digests->digest, digest, SM3256_SIZE);
			break;
		default:
			ret = -EINVAL;
			goto out;
		}

		ret = tpm2_extend_pcr(t, pcr, d);
	} else {
		ret = -EINVAL;
	}
out:
	return ret;
}

void free_tpm(struct tpm *t)
{
	tpm_relinquish_locality(t);
}
