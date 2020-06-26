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
 */

#ifndef _EARLY_TPM_H
#define _EARLY_TPM_H

/*** tpm_common.h ***/



#define TPM_MMIO_BASE		0xFED40000
#define TPM_MAX_LOCALITY	4

#define SHA1_SIZE	20
#define SHA256_SIZE	32
#define SHA384_SIZE	48
#define SHA512_SIZE	64
#define SM3256_SIZE	32

struct tpm_header {
	u16 tag;
	u32 size;
	u32 code;
} __attribute__ ((packed));

#define TPM_INTERFACE_ID_0	0x30
#define TPM_TIS_INTF_ACTIVE	0x00
#define TPM_CRB_INTF_ACTIVE	0x01

struct tpm_interface_id {
	union {
		u32 val;
		struct {
			u32 interface_type:4;
			u32 interface_version:4;
			u32 cap_locality:1;
			u32 reserved1:4;
			u32 cap_tis:1;
			u32 cap_crb:1;
			u32 cap_if_res:2;
			u32 interface_selector:2;
			u32 intf_sel_lock:1;
			u32 reserved2:4;
			u32 reserved3:8;
		};
	};
} __attribute__ ((packed));

#define TPM_INTF_CAPABILITY_0	0x14
#define TPM12_TIS_INTF_12	0x00
#define TPM12_TIS_INTF_13	0x02
#define TPM20_TIS_INTF_13	0x03

struct tpm_intf_capability {
	union {
		u32 val;
		struct {
			u32 data_avail_int_support:1;
			u32 sts_valid_int_support:1;
			u32 locality_change_int_support:1;
			u32 interrupt_level_high:1;
			u32 interrupt_level_low:1;
			u32 interrupt_edge_rising:1;
			u32 interrupt_edge_falling:1;
			u32 command_ready_int_support:1;
			u32 burst_count_static:1;
			u32 data_transfer_size_support:2;
			u32 reserved1:17;
			u32 interface_version:3;
			u32 reserved2:1;
		};
	};
} __attribute__ ((packed));

void tpm_mdelay(int ms);

/*
 * Timeouts defined in Table 16 from the TPM2 PTP and
 * Table 15 from the PC Client TIS
 */

/* TPM Timeout A: 750ms */
static inline void timeout_a(void)
{
	tpm_mdelay(750);
}

/* TPM Timeout B: 2000ms */
static inline void timeout_b(void)
{
	tpm_mdelay(2000);
}

/* Timeouts C & D are different between 1.2 & 2.0 */
/* TPM1.2 Timeout C: 750ms */
static inline void tpm1_timeout_c(void)
{
	tpm_mdelay(750);
}

/* TPM1.2 Timeout D: 750ms */
static inline void tpm1_timeout_d(void)
{
	tpm_mdelay(750);
}

/* TPM2 Timeout C: 200ms */
static inline void tpm2_timeout_c(void)
{
	tpm_mdelay(200);
}

/* TPM2 Timeout D: 30ms */
static inline void tpm2_timeout_d(void)
{
	tpm_mdelay(30);
}

/*
 * Durations derived from Table 15 of the PTP but is purely an artifact of this
 * implementation
 */

/* TPM Duration A: 20ms */
static inline void duration_a(void)
{
	tpm_mdelay(20);
}

/* TPM Duration B: 750ms */
static inline void duration_b(void)
{
	tpm_mdelay(750);
}

/* TPM Duration C: 1000ms */
static inline void duration_c(void)
{
	tpm_mdelay(1000);
}

u8 tpm_read8(u32 field);
void tpm_write8(unsigned char val, u32 field);
u32 tpm_read32(u32 field);
void tpm_write32(unsigned int val, u32 field);

/*** tis.h ***/

/* macros to access registers at locality ’’l’’ */
#define ACCESS(l)			(0x0000 | ((l) << 12))
#define STS(l)				(0x0018 | ((l) << 12))
#define DATA_FIFO(l)			(0x0024 | ((l) << 12))
#define DID_VID(l)			(0x0F00 | ((l) << 12))
/* access bits */
#define ACCESS_ACTIVE_LOCALITY		0x20 /* (R)*/
#define ACCESS_RELINQUISH_LOCALITY	0x20 /* (W) */
#define ACCESS_REQUEST_USE		0x02 /* (W) */
/* status bits */
#define STS_VALID			0x80 /* (R) */
#define STS_COMMAND_READY		0x40 /* (R) */
#define STS_DATA_AVAIL			0x10 /* (R) */
#define STS_DATA_EXPECT			0x08 /* (R) */
#define STS_GO				0x20 /* (W) */

static inline int tis_data_available(int locality)
{
	int status;

	status = tpm_read8(STS(locality));
	return ((status & (STS_DATA_AVAIL | STS_VALID)) ==
		(STS_DATA_AVAIL | STS_VALID));
}

/* TPM Interface Specification functions */
u8 tis_request_locality(u8 l);
void tis_relinquish_locality(void);
u8 tis_init(struct tpm *t);
size_t tis_send(struct tpmbuff *buf);
size_t tis_recv(enum tpm_family f, struct tpmbuff *buf);

/*** crb.h ***/

/* TPM Interface Specification functions */
u8 crb_request_locality(u8 l);
void crb_relinquish_locality(void);
u8 crb_init(struct tpm *t);
size_t crb_send(struct tpmbuff *buf);
size_t crb_recv(struct tpmbuff *buf);

/*** tpm1.h ***/



/* Section 2.2.3 */
#define TPM_AUTH_DATA_USAGE u8
#define TPM_PAYLOAD_TYPE u8
#define TPM_VERSION_BYTE u8
#define TPM_TAG u16
#define TPM_PROTOCOL_ID u16
#define TPM_STARTUP_TYPE u16
#define TPM_ENC_SCHEME u16
#define TPM_SIG_SCHEME u16
#define TPM_MIGRATE_SCHEME u16
#define TPM_PHYSICAL_PRESENCE u16
#define TPM_ENTITY_TYPE u16
#define TPM_KEY_USAGE u16
#define TPM_EK_TYPE u16
#define TPM_STRUCTURE_TAG u16
#define TPM_PLATFORM_SPECIFIC u16
#define TPM_COMMAND_CODE u32
#define TPM_CAPABILITY_AREA u32
#define TPM_KEY_FLAGS u32
#define TPM_ALGORITHM_ID u32
#define TPM_MODIFIER_INDICATOR u32
#define TPM_ACTUAL_COUNT u32
#define TPM_TRANSPORT_ATTRIBUTES u32
#define TPM_AUTHHANDLE u32
#define TPM_DIRINDEX u32
#define TPM_KEY_HANDLE u32
#define TPM_PCRINDEX u32
#define TPM_RESULT u32
#define TPM_RESOURCE_TYPE u32
#define TPM_KEY_CONTROL u32
#define TPM_NV_INDEX u32 The
#define TPM_FAMILY_ID u32
#define TPM_FAMILY_VERIFICATION u32
#define TPM_STARTUP_EFFECTS u32
#define TPM_SYM_MODE u32
#define TPM_FAMILY_FLAGS u32
#define TPM_DELEGATE_INDEX u32
#define TPM_CMK_DELEGATE u32
#define TPM_COUNT_ID u32
#define TPM_REDIT_COMMAND u32
#define TPM_TRANSHANDLE u32
#define TPM_HANDLE u32
#define TPM_FAMILY_OPERATION u32

/* Section 6 */
#define TPM_TAG_RQU_COMMAND		0x00C1
#define TPM_TAG_RQU_AUTH1_COMMAND	0x00C2
#define TPM_TAG_RQU_AUTH2_COMMAND	0x00C3
#define TPM_TAG_RSP_COMMAND		0x00C4
#define TPM_TAG_RSP_AUTH1_COMMAND	0x00C5
#define TPM_TAG_RSP_AUTH2_COMMAND	0x00C6

/* Section 16 */
#define TPM_SUCCESS 0x0

/* Section 17 */
#define TPM_ORD_EXTEND			0x00000014

#define SHA1_DIGEST_SIZE 20

/* Section 5.4 */
struct tpm_sha1_digest {
	u8 digest[SHA1_DIGEST_SIZE];
};
struct tpm_digest {
	TPM_PCRINDEX pcr;
	union {
		struct tpm_sha1_digest sha1;
	} digest;
};

#define TPM_DIGEST		struct tpm_sha1_digest
#define TPM_CHOSENID_HASH	TPM_DIGEST
#define TPM_COMPOSITE_HASH	TPM_DIGEST
#define TPM_DIRVALUE		TPM_DIGEST
#define TPM_HMAC		TPM_DIGEST
#define TPM_PCRVALUE		TPM_DIGEST
#define TPM_AUDITDIGEST		TPM_DIGEST
#define TPM_DAA_TPM_SEED	TPM_DIGEST
#define TPM_DAA_CONTEXT_SEED	TPM_DIGEST

struct tpm_extend_cmd {
	TPM_PCRINDEX pcr_num;
	TPM_DIGEST digest;
};

struct tpm_extend_resp {
	TPM_COMMAND_CODE ordinal;
	TPM_PCRVALUE digest;
};

/* TPM Commands */
int tpm1_pcr_extend(struct tpm *t, struct tpm_digest *d);

/*** tpm2.h ***/



/* Table 192  Definition of TPM2B_TEMPLATE Structure:
 *   Using this as the base structure similar to the spec
 */
struct tpm2b {
	u16 size;
	u8 buffer[0];
};

// Table 32  Definition of TPMA_SESSION Bits <  IN/OUT>
struct tpma_session {
	u8 continue_session  : 1;
	u8 audit_exclusive   : 1;
	u8 audit_reset       : 1;
	u8 reserved3_4       : 2;
	u8 decrypt           : 1;
	u8 encrypt           : 1;
	u8 audit             : 1;
};


// Table 72  Definition of TPMT_HA Structure <  IN/OUT>
struct tpmt_ha {
	u16 alg;	/* TPMI_ALG_HASH	*/
	u8 digest[0];	/* TPMU_HA		*/
};

// Table 100  Definition of TPML_DIGEST_VALUES Structure
struct tpml_digest_values {
	u32 count;
	struct tpmt_ha digests[0];
};


// Table 124  Definition of TPMS_AUTH_COMMAND Structure <  IN>
struct tpms_auth_cmd {
	u32 *handle;
	struct tpm2b *nonce;
	struct tpma_session *attributes;
	struct tpm2b *hmac;
};

// Table 125  Definition of TPMS_AUTH_RESPONSE Structure <  OUT>
struct tpms_auth_resp {
	struct tpm2b *nonce;
	struct tpma_session *attributes;
	struct tpm2b *hmac;
};

struct tpm2_cmd {
	struct tpm_header *header;
	u32 *handles;			/* TPM Handles array	*/
	u32 *auth_size;			/* Size of Auth Area	*/
	u8 *auth;			/* Authorization Area	*/
	u8 *params;			/* Parameters		*/
	u8 *raw;			/* internal raw buffer	*/
};

struct tpm2_resp {
	struct tpm_header *header;
	u32 *handles;		/* TPM Handles array	*/
	u32 *param_size;	/* Size of Parameters	*/
	struct tpm2b *params;	/* Parameters		*/
	u8 *auth;		/* Authorization Area	*/
	u8 *raw;		/* internal raw buffer	*/
};

int tpm2_extend_pcr(struct tpm *t, u32 pcr,
		struct tpml_digest_values *digests);

/*** tpm2_constants.h ***/


/* Table 9  Definition of (UINT16) TPM_ALG_ID Constants <IN/OUT, S> */
#define TPM_ALG_ERROR                (u16)(0x0000)
#define TPM_ALG_RSA                  (u16)(0x0001)
#define TPM_ALG_SHA                  (u16)(0x0004)
#define TPM_ALG_SHA1                 (u16)(0x0004)
#define TPM_ALG_HMAC                 (u16)(0x0005)
#define TPM_ALG_AES                  (u16)(0x0006)
#define TPM_ALG_MGF1                 (u16)(0x0007)
#define TPM_ALG_KEYEDHASH            (u16)(0x0008)
#define TPM_ALG_XOR                  (u16)(0x000A)
#define TPM_ALG_SHA256               (u16)(0x000B)
#define TPM_ALG_SHA384               (u16)(0x000C)
#define TPM_ALG_SHA512               (u16)(0x000D)
#define TPM_ALG_NULL                 (u16)(0x0010)
#define TPM_ALG_SM3_256              (u16)(0x0012)
#define TPM_ALG_SM4                  (u16)(0x0013)
#define TPM_ALG_RSASSA               (u16)(0x0014)
#define TPM_ALG_RSAES                (u16)(0x0015)
#define TPM_ALG_RSAPSS               (u16)(0x0016)
#define TPM_ALG_OAEP                 (u16)(0x0017)
#define TPM_ALG_ECDSA                (u16)(0x0018)
#define TPM_ALG_ECDH                 (u16)(0x0019)
#define TPM_ALG_ECDAA                (u16)(0x001A)
#define TPM_ALG_SM2                  (u16)(0x001B)
#define TPM_ALG_ECSCHNORR            (u16)(0x001C)
#define TPM_ALG_ECMQV                (u16)(0x001D)
#define TPM_ALG_KDF1_SP800_56A       (u16)(0x0020)
#define TPM_ALG_KDF2                 (u16)(0x0021)
#define TPM_ALG_KDF1_SP800_108       (u16)(0x0022)
#define TPM_ALG_ECC                  (u16)(0x0023)
#define TPM_ALG_SYMCIPHER            (u16)(0x0025)
#define TPM_ALG_CAMELLIA             (u16)(0x0026)
#define TPM_ALG_CTR                  (u16)(0x0040)
#define TPM_ALG_OFB                  (u16)(0x0041)
#define TPM_ALG_CBC                  (u16)(0x0042)
#define TPM_ALG_CFB                  (u16)(0x0043)
#define TPM_ALG_ECB                  (u16)(0x0044)
#define TPM_ALG_FIRST                (u16)(0x0001)
#define TPM_ALG_LAST                 (u16)(0x0044)

/* Table 12  Definition of (UINT32) TPM_CC Constants (Numeric Order) <IN/OUT, S> */
#define TPM_CC_PCR_EXTEND (u32)(0x00000182)

/* Table 19  Definition of (UINT16) TPM_ST Constants <IN/OUT, S> */
#define TPM_ST_NO_SESSIONS (u16)(0x8001)
#define TPM_ST_SESSIONS (u16)(0x8002)

/* Table 28  Definition of (TPM_HANDLE) TPM_RH Constants <S> */
#define TPM_RS_PW (u32)(0x40000009)

/*** tpm2_auth.h ***/

#endif
