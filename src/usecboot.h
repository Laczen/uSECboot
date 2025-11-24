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

enum usecboot_error {
	USECBOOTERR_NONE = 0,	 /* No error */
	USECBOOTERR_ENOENT = 2,	 /* No such file or directory */
	USECBOOTERR_EFAULT = 14, /* Bad address */
	USECBOOTERR_EINVAL = 22, /* Invalid argument */
};

struct usecboot_slot;

STRUCT_PACKED usecboot_slotapi {
	int (*prep)(const struct usecboot_slot *slot);
	int (*read)(const struct usecboot_slot *slot, uint32_t start,
		    void *data, size_t len);
	void (*boot)(const struct usecboot_slot *slot, uint32_t ioff);
	void (*clean)(const struct usecboot_slot *slot);
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
 * rc = usecboot_get_tlv(slot, &version, NULL);
 *
 */

int usecboot_get_tlv(const struct usecboot_slot *slot,
		     void *tlv, uint32_t *pos);

/* The following routine can be used by the port to calculate a hmac over
 * a certain range of data in a slot. The routine uses the read routine
 * provided in the slot api.
 *
 * Parameters:
 * slot:     the slot where data resides,
 * off:      start position of data,
 * len:	     length of data,
 * key:      pointer to private key used in hmac,
 * key_len:  length of the key,
 * hmac:     hmac output,
 * hmac_len: length of the hmac,
 * Return: -USECBOOTERR_EFAULT on failure, 0 otherwise.
 */

int usecboot_hmac_calc(const struct usecboot_slot *slot, uint32_t off,
		       size_t len, const uint8_t *key, size_t key_len,
		       uint8_t *hmac, size_t hmac_len);

/* The following routine can be used by the port to verify a hmac over
 * a certain range of data in a slot. The routine uses the read routine
 * provided in the slot api.
 *
 * Parameters:
 * slot:     the slot where data resides,
 * off:      start position of data,
 * len:	     length of data,
 * key:      pointer to private key used in hmac,
 * key_len:  length of the key,
 * hmac:     hmac input,
 * hmac_len: length of the hmac,
 * Return: 0 on match, 1 otherwise.
 */

int usecboot_hmac_vrfy(const struct usecboot_slot *slot, uint32_t off,
		       size_t len, const uint8_t *key, size_t key_len,
		       const uint8_t *hmac, size_t hmac_len);

/*
 * The following routine needs to be provided by the port, it should return
 * a pointer to the slot or NULL in case of invalid idx or error.
 */

const struct usecboot_slot *usecboot_get_slot(uint8_t idx);

/*
 * The following routine needs to be provided by the port, it should copy
 * the root pubkey.
 * The routine should return:
 *   USECBOOTERR_NONE: requested root pubkey matches len and is set,
 *   -USECBOOTERR_EINVAL: requested root pubkey len does not match.
 */

int usecboot_get_rootpkey(void *pkey, size_t len);

/*
 * The following routine needs to be provided by the port, it should provide
 * any rejected pubkey that has the correct length.
 * The routine should return:
 *   USECBOOTERR_NONE: rejected pubkey and the size matches "len",
 *   -USECBOOTERR_ENOENT: no more rejected pubkey entries,
 *   -USECBOOTERR_EINVAL: pubkey size does not match "len",
 *
 * When no rejected pubkeys are available and/or this feature is not supported
 * it should return -USECBOOTERR_ENOENT.
 */

int usecboot_get_rejected_pubkey(uint32_t idx, uint8_t *pubkey, size_t len);

/*
 * The following routine needs to be provided by the port, it should output
 * the log message.
 */

void usecboot_log(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* USECBOOT_H_ */