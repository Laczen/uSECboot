/*
 * Copyright (c) 2024 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * usec-boot provides routines to build a simple secure bootloader,
 * this header provides the private interface and structures.
 */

#ifndef USECBOOT_PRIV_H_
#define USECBOOT_PRIV_H_

/* TAGS 0x10..0x1f are reserved for signatures */
#define USECBOOT_SIGN_TAG_ED25519	0x10

/* The signature tag defines the used pubkey and hashes to keep the
 * bootloader size small. There is no need to support multiple tags
 * for the stored hashes and pubkeys. Let us defined the used tags
 */
#define USECBOOT_END_TAG	0xFF
#define USECBOOT_END_LEN	0x00
#define USECBOOT_SIGN_TAG	USECBOOT_SIGN_TAG_ED25519
#define USECBOOT_PKEY_TAG	0x20
#define USECBOOT_HASH_TAG	0x21

#if USECBOOT_SIGN_TAG == USECBOOT_SIGN_TAG_ED25519
#define USECBOOT_PKEY_SIZE 32
#define USECBOOT_SIGN_SIZE 64
#endif

#ifdef CONFIG_USECBOOT_HASH_SIZE
#define USECBOOT_HASH_SIZE CONFIG_USECBOOT_HASH_SIZE
#else
#define USECBOOT_HASH_SIZE 32
#endif

#include "usecboot.h"

#define USECBOOT_SEED 0x9E3779B9

STRUCT_PACKED usecboot_hash_tlv {
	struct usecboot_tlv_hdr hdr;
	uint8_t offset[4];	/* offset from start of header in big endian */
	uint8_t msg_size[4];	/* message size in big endian */
	uint8_t hash[USECBOOT_HASH_SIZE];
};

/* The message that is signed is prepending the signature tlv, the message
 * length is determined by msg_size.
 */
STRUCT_PACKED usecboot_signature_tlv {
	struct usecboot_tlv_hdr hdr;
	uint8_t msg_size[4];	/* message size in big endian */
	uint8_t signature[USECBOOT_SIGN_SIZE];
};

STRUCT_PACKED usecboot_pubkey_tlv {
	struct usecboot_tlv_hdr hdr;
	uint8_t pubkey[USECBOOT_PKEY_SIZE];
	struct usecboot_signature_tlv signature;
};

#define CONFIG_USECBOOT_LOG 1

#ifdef CONFIG_USECBOOT_LOG
#define USECBOOT_LOG(...) usecboot_log(__VA_ARGS__)
#else
#define USECBOOT_LOG(...) ((void)0)
#endif

#endif /* USECBOOT_PRIV_H_ */