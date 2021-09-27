Security Kernel Loader
######################

The Security Kernel Loader (SKL) is an implementation of AMD's  Secure Loader
Block (SLB) specification for the SKINIT CPU instruction and DRTM measurements.
The SKL loader takes a minimal approach relying on the DRTM Preamble, e.g. the
system bootloader, to load into memory and configure the Security Kernel that
the SKL will measure and execute. This document details the boot protocol that
a DRTM Preamble must implement to properly launch the SKL. This protocol is
versioned and future revisions may be expanded in a manner that provides
backwards compatibility.

+----------+---------------------------------------------------------+
| Protocol | Notes                                                   |
| Version  |                                                         |
+==========+=========================================================+
|    1     | Initial protocol                                        |
+----------+---------------------------------------------------------+

SKL Setup
*********

The DRTM Preamble is responsible for allocating a contiguous block of physical
memory and will ensure it is marked as reserved in the system memory map. The
necessary size for the allocation will be found in the SKL header. The DRTM
Preamble will place the SKL at the beginning of the allocation.

Below is a representation of SKL memory for visual purposes. The boot tags will
always be the last region, otherwise there are no guaranteed locations for the
remaining segments and must be located thorugh the SKL header.::

      +---      Security Kernel Loader (64kb)      ---+
      |                                               |
      v                                               v
      +--------+----------+----------+-----------+--------------+
      | Header |   Code   | Log Area | Boot Tags | Scratch Area |
      +--------+----------+----------+-----------+--------------+
      ^                   ^          ^           ^              ^
      |                   |          |           |              |
      +                   +          +           +              +
   skl_base            hdr.log    hdr.tags     <60kb     hdr.alloc_size


SKL Header
==========

The SKL header is the SLB header which has been extended to meet the
needs of the SKL. The first two fields are mandated by the SLB and the SKL adds
two additional fields which can be seen in the following representative struct,
::

    struct skl_hdr {
        u16 entry_point;        /* Code Entry */
        u16 length;             /* RoT Measurement Length */
        u16 alloc_size;         /* Allocation Size */
        u16 info_table_offset;  /* Offset for the SKL Info Table */
        u16 logs_offset;        /* Offset for the SKL Info Table */
        u16 boot_tags_offset;   /* RoT Measurement Length */
    };

SKL Allocation Size
-------------------

The allocation size reflects the amount of memory required for the SLK and its scratch
area. The DRTM Preamble should allocate at least header.alloc_size bytes of contiguous memory
and make the area reserved in the system memory map.

Info Table
==========

The Info Table contains a description of the SKL, specifically a unique
identifier and the version for the SKL. This is version 1 of  Future versions may
extend this structure in a backwards compatible manor.
::

    struct skl_info {
        u8 uuid[16]; /* 78 f1 26 8e 04 92 11 e9  83 2a c8 5b 76 c4 cc 02 */
        u8 major;  /* Version major of the SKL */
        u8 minor;  /* Version minor of the SKL */
        u16 protocol; /* Boot protocol supported */
    } __packed;

    
Boot Tags
=========

The Boot Tags are a series of Tag/Length/Value entries for the DRTM Preamble to
pass information to the SKL. As a result the Boot Tags will be the last segment
before the Scratch Area and therefore cannot exceed a byte offset of 61440
bytes

Each Boot Tag has its first element, a `struct skl_tag_hdr`, where the `type`
consists of a four bit class and a four bit subtype.  This provides a single
tier hierarchy which enable each class to have different rules dictating their
usage, e.g. there can only be one boot class tag.
::

    struct skl_tag_hdr {
        u8 type;
        u8 len;
    } __packed;


Boot Class
----------

The Boot Class tags are for selecting the which boot protocol to use to start
the target kernel. Currently only two boot protocols are supported, the Linux
boot protocol and the Multiboot2 protocol.

Linux Boot Tag
^^^^^^^^^^^^^^

The SKL relies on the DRTM Preamble to setup and stage the Linux kernel for
booting, therefore the SKL only requires to be provided the location of the
kernel's zero page to enable measuring and starting the Linux kernel.
::

    struct skl_tag_boot_linux {
        struct skl_tag_hdr hdr;
        u32 zero_page;
    } __packed;

Multiboot2 Boot Tag
^^^^^^^^^^^^^^^^^^^

The SKL relies on the DRTM Preamble to setup the Multiboot2 module list and
must be provided the address for the Multiboot2 Boot Information (MBI) module
and may optionally include the entry address and size of the kernel to be
started.
::

    struct lz_tag_boot_mb2 {
        struct skl_tag_hdr hdr;
        u32 mbi;        
        u32 kernel_entry;
        u32 kernel_size;
    } __packed;

Linux Class
-----------

This class is for any boot information created/generated by the SKL that needs
to be passed along to the Linux kernel.

Setup Data Tag
^^^^^^^^^^^^^^

The Linux Secure Launch protocol requires a Setup Indirect setup data entry to
pass information to Secure Launch. This resulting structure is chained into
Linux's `struct setup_header->setup_data` linked list.
::

    struct skl_tag_setup_data {
        struct skl_tag_hdr hdr;
        struct setup_data data;
    } __packed;

Logging Class
-------------

The logging class holds the tags related to the TPM Event log and SKL's
internal logging facilities.

Event Log Tag
^^^^^^^^^^^^^

The Event Log tag provides three controls, policy, scheme, and the address/size
of the event log.  The policy controls how and what algorithms will be used,
scheme allows for selecting the PCR usage scheme, and address/size provides the
address and size of the event log buffer setup by the DRTM Preamble. The DRTM
Preamble will use the address/size from the DRTM ACPI table or it will allocate
and reserve a memory region to be used as the event log buffer.
::

    struct skl_tag_evtlog {  
        struct skl_tag_hdr hdr;
        u16 policy;
        u16 scheme;
        u32 address;       
        u32 size;       
    } __packed;             

CRTM Hash Tag
^^^^^^^^^^^^^

The SKINIT instruction does not provide the measurement it made of the SKL to
the SKL iteslf, but the value needs to be present in the Event Log for
attestation purposes. This tag provides the option for the DRTM Preamble to
hash the SKL and provide the measurement to the SKL for recording into the log.
::

    struct skl_tag_crtm_hash {
        struct skl_tag_hdr hdr;
        u16 algo_id;
        u8 digest[];
    } __packed;

MSB Class
---------

The Measured Secure Boot (MSB) is an upcoming optional operational mode of the
SKL. It allows for the SKL to function as the Root of Trust for Verification
(RTV) for a SecureBoot trust chain using a public key provided to SKL. The MSB
Class is for all tags relating to configuring MSB.

MSB Key Tag
^^^^^^^^^^^

The MSK Key tag is to allow embedding an MSB key directly into SKL.
::

    struct skl_tag_msb_key {
        struct skl_tag_hdr hdr;
        u16 algo_id;
        u8 key[];
    } __packed;

MSB Key DB Tag
^^^^^^^^^^^^^^

The MSK Key DB tag points to a key db list external to the SKL along with a
hash of the db list.
::

    struct skl_tag_msb_keydb {
        struct skl_tag_hdr hdr;
        u32 keydb;
        u32 size;
        u16 algo_id;
        u8 digest[];
    } __packed;
