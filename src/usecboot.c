#include "monocypher-ed25519.h"
#include "usecboot_priv.h"

#ifndef CONFIG_USECBOOT_MAX_HDRSIZE
#define CONFIG_USECBOOT_MAX_HDRSIZE 1024
#endif

/* To reduce stack usage we define one static buffer to use when reading data,
 * select its size to be equal to the maximum header size to allow validating
 * the header signature.
 */
static uint8_t msg[CONFIG_USECBOOT_MAX_HDRSIZE];

static void usecboot_cpy(void *d1, const void *d2, size_t size)
{
	uint8_t *p1 = d1;
	const uint8_t *p2 = d2;

	for (size_t i = 0; i < size; i++) {
		p1[i] = p2[i];
	}
}

static uint32_t usecboot_getbe32(uint8_t *data)
{
	return ((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]);
}

static int usecboot_read(const struct usecboot_slot *slot, uint32_t start,
			 void *data, size_t len)
{
	if ((slot->size < start) || ((slot->size - start) < len)) {
		return -USECBOOTERR_EINVAL;
	}

	return slot->api->read(slot, start, data, len);
}

/* To get a specific tlv: fill in the tlv header of a pointer to the
 * desired tlv with the TAG and the size and call usecboot_get_tlv
 */
int usecboot_get_tlv(const struct usecboot_slot *slot,
		     void *tlv, uint32_t *pos)
{
	struct usecboot_tlv_hdr *hdr = (struct usecboot_tlv_hdr *)tlv;
	struct usecboot_tlv_hdr wlk;
	uint32_t rdpos = 0;
	int rc = 0;

	for (;;) {
		if (rdpos > CONFIG_USECBOOT_MAX_HDRSIZE) {
			rc = -USECBOOTERR_ENOENT;
			goto err_out;
		}

		rc = usecboot_read(slot, rdpos, (void *)&wlk, sizeof(wlk));
		if (rc != USECBOOTERR_NONE) {
			goto err_out;
		}

		if ((wlk.tag == USECBOOT_END_TAG) ||
		    (wlk.len == USECBOOT_END_LEN)) {
			rc = -USECBOOTERR_ENOENT;
			goto err_out;
		}

		if ((wlk.tag == hdr->tag) && (wlk.len == hdr->len)) {
			if (pos != NULL) {
				*pos = rdpos;
			}
			break;
		}

		rdpos += wlk.len;
	}

	return usecboot_read(slot, rdpos, tlv, wlk.len);
err_out:
	USECBOOT_LOG("Missing TLV with tag %x\r\n", hdr->tag);
	return rc;
}

static int usecboot_get_pkey(const struct usecboot_slot *slot,
			     struct usecboot_pubkey_tlv *pktlv)
{
	uint8_t rootpkey[USECBOOT_PKEY_SIZE];
	uint32_t pos = 0;
	size_t msize;
	int rc;

	rc = usecboot_get_rootpkey(rootpkey, sizeof(rootpkey));
	if (rc != USECBOOTERR_NONE) {
		goto err_out;
	}

	pktlv->hdr.tag = USECBOOT_PKEY_TAG;
	pktlv->hdr.len = sizeof(struct usecboot_pubkey_tlv);

	rc = usecboot_get_tlv(slot, pktlv, &pos);

	if (rc == -USECBOOTERR_ENOENT) {
		/* set the pubkey to the root pubkey */
		USECBOOT_LOG("Missing public key, using root public key\r\n");
		usecboot_cpy(pktlv->pubkey, rootpkey, USECBOOT_PKEY_SIZE);
		goto ok_out;
	}

	msize = usecboot_getbe32(pktlv->signature.msg_size);
	if ((rc != USECBOOTERR_NONE) || (msize != USECBOOT_PKEY_SIZE)) {
		goto err_out;
	}

#if CONFIG_USECBOOT_MAX_REJECTED_PKEY != 0
	/* Is the pubkey on the list of rejected pubkeys ? */
	for (uint32_t i = 0U; i < CONFIG_USECBOOT_MAX_REJECTED_PKEY; i++) {
		rc = usecboot_get_rejected_pubkey(i, msg, USECBOOT_PKEY_SIZE);
		if (rc == USECBOOTERR_ENOENT) {
			break;
		}

		rc = usecboot_cmp(msg, pktlv->pubkey, USECBOOT_PKEY_SIZE);
		if (rc == 0) {
			/* The pubkey has been rejected */
			USECBOOT_LOG("Invalid public key\r\n")
			goto err_out;
		}
	}
#endif

	/* set the position to the start of the signature tlv */
	pos += sizeof(struct usecboot_pubkey_tlv);
	pos -= sizeof(struct usecboot_signature_tlv);
	rc = usecboot_read(slot, pos - msize, (void *)msg, msize);

	if (rc != USECBOOTERR_NONE) {
		goto err_out;
	}

	/* Verify the pubkey using the root pubkey */
	rc = crypto_ed25519_check(pktlv->signature.signature, rootpkey, msg,
				  msize);
	if (rc != 0) {
		USECBOOT_LOG("Invalid public key\r\n");
		goto err_out;
	}

ok_out:
	return USECBOOTERR_NONE;
err_out:
	return -USECBOOTERR_EFAULT;
}

static int usecboot_signature_ok(const struct usecboot_slot *slot)
{
	struct usecboot_pubkey_tlv pktlv;
	struct usecboot_signature_tlv sigtlv = {
		.hdr.tag = USECBOOT_SIGN_TAG,
		.hdr.len = sizeof(sigtlv),
	};
	uint32_t pos;
	size_t msize;
	int rc;

	rc = usecboot_get_pkey(slot, &pktlv);
	if (rc != USECBOOTERR_NONE) {
		goto err_out;
	}

	rc = usecboot_get_tlv(slot, &sigtlv, &pos);
	if (rc != USECBOOTERR_NONE) {
		goto err_out;
	}

	msize = usecboot_getbe32(sigtlv.msg_size);
	if ((msize > pos) || (msize > CONFIG_USECBOOT_MAX_HDRSIZE)) {
		goto err_out;
	}

	rc = usecboot_read(slot, pos - msize, (void *)msg, msize);
	if (rc != USECBOOTERR_NONE) {
		goto err_out;
	}

	rc = crypto_ed25519_check(sigtlv.signature, pktlv.pubkey, msg, msize);
	if (rc != 0) {
		goto err_out;
	}

	return USECBOOTERR_NONE;
err_out:
	USECBOOT_LOG("Invalid signature\r\n");
	return -USECBOOTERR_EFAULT;
}

static int usecboot_hash_ok(const struct usecboot_slot *slot, uint32_t *ioff)
{
	struct usecboot_hash_tlv hashtlv = {
		.hdr.tag = USECBOOT_HASH_TAG,
		.hdr.len = sizeof(hashtlv),
	};
	uint32_t off;
	size_t len;
	int rc;

	rc = usecboot_get_tlv(slot, &hashtlv, NULL);

	if (rc != USECBOOTERR_NONE) {
		goto err_out;
	}

	off = usecboot_getbe32(hashtlv.offset);
	len = usecboot_getbe32(hashtlv.msg_size);
	*ioff = off;

	slot->api->hash_init(slot);
	while (len != 0) {
		const size_t rdlen = len < sizeof(msg) ? len : sizeof(msg);

		rc = usecboot_read(slot, off, (void *)msg, rdlen);
		if (rc != USECBOOTERR_NONE) {
			break;
		}

		slot->api->hash_update(slot, msg, rdlen);
		off += rdlen;
		len -= rdlen;
	}

	if (slot->api->hash_cmp(slot, hashtlv.hash, USECBOOT_HASH_SIZE) != 0) {
		goto err_out;
	}

	return USECBOOTERR_NONE;
err_out:
	*ioff = 0U;
	USECBOOT_LOG("Invalid image hash\r\n");
	return -USECBOOTERR_EFAULT;
}

void usecboot_boot(void)
{
	uint8_t idx = 0;

	USECBOOT_LOG("==== Welcome to uSECboot ====\r\n");

	for (;;) {
		const struct usecboot_slot *slot=usecboot_get_slot(idx);
		uint32_t img_off;

		if ((slot == NULL) || (slot->size == 0U) ||
		    (slot->api == NULL)) {
			break;
		}

		if ((slot->api->prep == NULL) ||
		    (slot->api->read == NULL) ||
		    (slot->api->boot == NULL) ||
		    (slot->api->hash_init == NULL) ||
		    (slot->api->hash_update == NULL) ||
		    (slot->api->hash_cmp == NULL)) {
			USECBOOT_LOG("Missing required slot API routines\r\n");
			continue;
		}

		if (slot->api->prep(slot) != 0) {
			USECBOOT_LOG("Slot preparation failed\r\n");
			continue;
		}

		if ((usecboot_signature_ok(slot) == USECBOOTERR_NONE) &&
		    (usecboot_hash_ok(slot, &img_off) == USECBOOTERR_NONE) &&
		    (img_off < slot->size)) {
			USECBOOT_LOG("Booting image idx %d from offset %x\r\n",
				     idx, img_off);
			slot->api->boot(slot, img_off);
			USECBOOT_LOG("Boot failed\r\n");
		} else {
			USECBOOT_LOG("Verify failed\r\n");
			if (slot->api->clean != NULL) {
				slot->api->clean(slot);
			}
		}

		USECBOOT_LOG("Trying next slot...\r\n");
		idx++;
	}

	USECBOOT_LOG("Nothing to boot, spinning...\r\n");
	for (;;);
}
