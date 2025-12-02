/*
 * Copyright (c) 2024 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * usec-boot provides routines to build a simple secure bootloader,
 * this header provides the public interface and structures.
 */

#ifndef USECBOOT_H_
#define USECBOOT_H_

#if defined(STRUCT_PACKED)
#undef STRUCT_PACKED
#endif

#define STRUCT_PACKED struct __attribute__((__packed__))

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

enum usecboot_rc_values {
	USECBOOTOK = 0x4B434F52,	/* "RCOK" No error */
	USECBOOTERR = 0x4C464352,	/* "RCFL" Failure */
};

struct usecboot_slot;

STRUCT_PACKED usecboot_slot_state {
	uint32_t seed;
	uint32_t hsig;
	uint32_t hshs;
	uint32_t ioff;
	uint32_t chksum;
};

STRUCT_PACKED usecboot_slotapi {
	int (*read)(const struct usecboot_slot *slot, uint32_t start,
		    void *data, size_t len);
	void (*boot)(const struct usecboot_slot *slot, uint32_t ioff);
	void (*hash_init)(const struct usecboot_slot *slot);
	void (*hash_update)(const struct usecboot_slot *slot, const void *msg,
			    size_t msglen);
	int (*hash_cmp)(const struct usecboot_slot *slot, const void *hash,
			size_t hash_len);
};

STRUCT_PACKED usecboot_slot {
	const size_t size;
	const struct usecboot_slotapi *api;
};

STRUCT_PACKED usecboot_tlv_hdr {
	uint8_t tag;
	uint8_t len;
};

/*
 * The following routine is used by the port, it is the only routine that
 * needs to be called in main and will never return
 */

void usecboot_boot(void);

/* The following routine can be used by the port to retrieve custom TLV's
 * in the slot routines prep, read, boot or clean. This can be used e.g.
 * to check if there is a match between the board and the firmware.
 * To get a specific tlv: fill in the tlv header of a pointer to the
 * desired tlv with the TAG and the size and call usecboot_get_tlv.
 *
 * E.g. to get a image version that has been added to a tlv as:
 * struct version_tlv {
 *      usecboot_tlv_hdr hdr;
 *      uint8_t major;
 *      uint8_t minor;
 *      uint16_t patch;
 * };
 * struct version_tlv version = {
 *	.hdr.tag = 0x31,
 *      .hdr.len = sizeof(version),
 * };
 * int rc = usecboot_get_tlv(slot, &version, NULL);
 *
 * Return code: USECBOOTOK if found, USECBOOTERR if failed.
 */

int usecboot_tlv(const struct usecboot_slot *slot, void *tlv, uint32_t *pos);

/*
 * The following routine needs to be provided by the port, it should return
 * a pointer to the slot or NULL in case of invalid idx or error.
 */

const struct usecboot_slot *usecboot_slot(uint8_t idx);

/*
 * The following routine needs to be provided by the port, it should provide
 * the root pubkey.
 *
 * Return code: USECBOOTOK if set, USECBOOTERR if failed.
 */

int usecboot_rootpkey(void *pkey, size_t len);

/*
 * The following routine needs to be provided by the port, it should verify
 * if the pubkey is still allowed to be used (not on a list of rejected pubeys)
 *
 * Return code: USECBOOTOK if allowed, USECBOOTERR if not allowed.
 */

int usecboot_allowed_pubkey(uint8_t *pubkey, size_t len);

/*
 * The following routine needs to be provided by the port, it should output
 * the log message.
 */

void usecboot_log(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* USECBOOT_H_ */