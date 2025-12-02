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

static uint32_t usecboot_getbe32(const uint8_t *data)
{
	return ((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]);
}

static int usecboot_read(const struct usecboot_slot *slot, uint32_t start,
			 void *data, size_t len)
{
	if ((slot->size < start) || ((slot->size - start) < len)) {
		return USECBOOTERR;
	}

	return slot->api->read(slot, start, data, len);
}

/* To retrieve a specific tlv: fill in the tlv header of a pointer to the
 * desired tlv with the TAG and the size and call usecboot_get_tlv
 */
int usecboot_tlv(const struct usecboot_slot *slot, void *tlv, uint32_t *pos)
{
	struct usecboot_tlv_hdr *hdr = (struct usecboot_tlv_hdr *)tlv;
	struct usecboot_tlv_hdr wlk;
	uint32_t rdpos = (pos == NULL) ? 0U : (*pos);

	for (;;) {
		if (rdpos > CONFIG_USECBOOT_MAX_HDRSIZE) {
			goto err_out;
		}

		if (usecboot_read(slot, rdpos, (void *)&wlk, sizeof(wlk)) !=
		    USECBOOTOK) {
			goto err_out;
		}

		if ((wlk.tag == USECBOOT_END_TAG) ||
		    (wlk.len == USECBOOT_END_LEN)) {
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

	if (usecboot_read(slot, rdpos, tlv, wlk.len) != USECBOOTOK) {
		goto err_out;
	}

	return USECBOOTOK;
err_out:
	return USECBOOTERR;
}

static int usecboot_crypto_check(uint8_t *signature, uint8_t *pubkey,
				 uint8_t *msg, size_t msglen)
{
	if (crypto_ed25519_check(signature, pubkey, msg, msglen) != 0) {
		return USECBOOTERR;
	}

	return USECBOOTOK;
}

static int usecboot_get_pkey(const struct usecboot_slot *slot,
			     struct usecboot_pubkey_tlv *pktlv)
{
	uint8_t rootpkey[USECBOOT_PKEY_SIZE];
	uint32_t pos = 0U;
	size_t msize;
	int rc = usecboot_rootpkey(rootpkey, sizeof(rootpkey));

	if (rc != USECBOOTOK) {
		goto err_out;
	}

	pktlv->hdr.tag = USECBOOT_PKEY_TAG;
	pktlv->hdr.len = sizeof(struct usecboot_pubkey_tlv);

	rc = usecboot_tlv(slot, pktlv, &pos);
	if (rc == USECBOOTERR) {
		/* set the pubkey to the root pubkey */
		USECBOOT_LOG("Missing public key, using root public key\r\n");
		usecboot_cpy(pktlv->pubkey, rootpkey, USECBOOT_PKEY_SIZE);
		rc = USECBOOTOK;
		return rc;
	}

	msize = usecboot_getbe32(pktlv->signature.msg_size);
	if (msize != USECBOOT_PKEY_SIZE) {
		rc = USECBOOTERR;
		goto err_out;
	}

	rc = usecboot_allowed_pubkey(pktlv->pubkey, USECBOOT_PKEY_SIZE);
	if (rc != USECBOOTOK) {
		goto err_out;
	}

	/* set the position to the start of the signature tlv */
	pos += sizeof(struct usecboot_pubkey_tlv);
	pos -= sizeof(struct usecboot_signature_tlv);
	rc = usecboot_read(slot, pos - msize, (void *)msg, msize);
	if (rc != USECBOOTOK) {
		goto err_out;
	}

	/* Verify the pubkey using the root pubkey */
	rc = usecboot_crypto_check(pktlv->signature.signature, rootpkey, msg,
				   msize);
	if (rc != USECBOOTOK) {
		goto err_out;
	}

	return rc;
err_out:
	USECBOOT_LOG("Invalid public key\r\n");
	return rc;
}

static void usecboot_verify_signature(const struct usecboot_slot *slot,
				      volatile struct usecboot_slot_state *state)
{
	struct usecboot_pubkey_tlv pktlv;
	struct usecboot_signature_tlv sigtlv = {
		.hdr.tag = USECBOOT_SIGN_TAG,
		.hdr.len = sizeof(sigtlv),
	};
	uint32_t pos = 0U;
	size_t msz;

	state->hsig = state->seed ^ USECBOOTERR;
	if (usecboot_get_pkey(slot, &pktlv) != USECBOOTOK) {
		goto err_out;
	}

	if (usecboot_tlv(slot, &sigtlv, &pos) != USECBOOTOK) {
		goto err_out;
	}

	msz = usecboot_getbe32(sigtlv.msg_size);
	if ((msz > pos) || (msz > CONFIG_USECBOOT_MAX_HDRSIZE)) {
		goto err_out;
	}

	if (usecboot_read(slot, pos - msz, (void *)msg, msz) != USECBOOTOK) {
		goto err_out;
	}


	if (usecboot_crypto_check(sigtlv.signature, pktlv.pubkey, msg, msz) !=
	    USECBOOTOK) {
		goto err_out;
	}

	state->hsig = state->seed ^ USECBOOTOK;
err_out:
}

static int usecboot_verify_hash(const struct usecboot_slot *slot,
				const struct usecboot_hash_tlv *hash_tlv)
{
	uint32_t off = usecboot_getbe32(hash_tlv->offset);
	size_t len = usecboot_getbe32(hash_tlv->msg_size);

	slot->api->hash_init(slot);
	while (len != 0) {
		const size_t rdlen = len < sizeof(msg) ? len : sizeof(msg);

		if (usecboot_read(slot, off, (void *)msg, rdlen) !=
		    USECBOOTOK) {
			break;
		}

		slot->api->hash_update(slot, msg, rdlen);
		off += rdlen;
		len -= rdlen;
	}

	if (slot->api->hash_cmp(slot, hash_tlv->hash, USECBOOT_HASH_SIZE) !=
	    USECBOOTOK) {
		goto err_out;
	}

	if (len != 0U) {
		goto err_out;
	}

	return USECBOOTOK;
err_out:
	return USECBOOTERR;
}

static void usecboot_verify_hashes(const struct usecboot_slot *slot,
				   volatile struct usecboot_slot_state *state)
{
	struct usecboot_hash_tlv hashtlv = {
		.hdr.tag = USECBOOT_HASH_TAG,
		.hdr.len = sizeof(hashtlv),
	};
	uint32_t pos = 0U;
	uint32_t hcnt = 0U;


	state->hshs = state->hsig ^ USECBOOTERR;
	while (usecboot_tlv(slot, &hashtlv, &pos) == USECBOOTOK) {
		if (usecboot_verify_hash(slot, &hashtlv) != USECBOOTOK) {
			goto err_out;
		}

		if (hcnt == 0U) {
			state->ioff = usecboot_getbe32(hashtlv.offset);
		}

		pos += sizeof(hashtlv);
		hcnt++;
	}

	if (hcnt == 0U) {
		goto err_out;
	}

	state->hshs = state->hsig ^ USECBOOTOK;
	return;
err_out:
	state->ioff = 0U;
}

void usecboot_verify(const struct usecboot_slot *slot,
		     volatile struct usecboot_slot_state *state)
{
	state->seed = USECBOOT_SEED;
	usecboot_verify_signature(slot, state);
	state->hsig ^= (uint32_t)((void *)usecboot_verify_signature);
	usecboot_verify_hashes(slot, state);
	state->hshs ^= (uint32_t)((void *)usecboot_verify_hashes);
	state->ioff ^= state->hshs;
	state->chksum = state->seed ^ state->hsig ^ state->hshs ^ state->ioff;
}

int usecboot_validate(volatile const struct usecboot_slot_state *state)
{
	uint32_t chk;

	chk = state->seed ^ state->hsig ^ state->hshs ^state->ioff;
	if (state->chksum != chk) {	/* tampering detected spin */
		USECBOOT_LOG("Tampering detected/r/n");
		for (;;);
	}

	chk = (uint32_t)((void *)usecboot_verify_signature);
	chk ^= state->seed ^ state->hsig;
	if (chk != USECBOOTOK) {	/* bad signature */
		USECBOOT_LOG("Invalid signature/r/n");
		return USECBOOTERR;
	}

	chk = (uint32_t)((void *)usecboot_verify_hashes);
	chk ^= state->hsig ^ state->hshs;
	if (chk != USECBOOTOK) {	/* bad hash */
		USECBOOT_LOG("Invalid hash/r/n");
		return USECBOOTERR;
	}

	return USECBOOTOK;
}

uint32_t usecboot_ioff(volatile const struct usecboot_slot_state *state)
{
	return state->ioff ^ state->hshs;
}

void usecboot_boot(void)
{
	uint8_t idx = 0;

	USECBOOT_LOG("==== Welcome to uSECboot ====\r\n");
	for (;;) {
		const struct usecboot_slot *slot = usecboot_slot(idx);
		volatile struct usecboot_slot_state state;

		if ((slot == NULL) || (slot->api == NULL)) {
			break;
		}

		idx++;
		if ((slot->api->read == NULL) ||
		    (slot->api->boot == NULL) ||
		    (slot->api->hash_init == NULL) ||
		    (slot->api->hash_update == NULL) ||
		    (slot->api->hash_cmp == NULL)) {
			USECBOOT_LOG("Slot api routines error, skipping.\r\n");
			continue;
		}

		if (slot->size == 0U) {
			USECBOOT_LOG("Slot size zero, skipping\r\n");
			continue;
		}

		usecboot_verify(slot, &state);
		if (usecboot_validate(&state) == USECBOOTOK) {
			USECBOOT_LOG("Booting image idx %d from offset %x\r\n",
				     idx, usecboot_ioff(&state));
			slot->api->boot(slot, usecboot_ioff(&state));
		}

		USECBOOT_LOG("Boot failed\r\n");
	}

	USECBOOT_LOG("Nothing to boot, spinning...\r\n");
	for (;;);
}
