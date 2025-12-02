# uSECboot
uSECboot is a libary of routines to create a secure bootloader.

Images booted by uSECboot are signed with a Ed25519 signature. Ed25519 is a
high-performance and secure digital signature algorithm that uses the EdDSA
standard and the Curve25519 elliptic curve. It is known for its speed in both
signing and verification, its strong security against various attacks, and
simple implementation, which minimizes developer error. Ed25519 is a popular
choice for modern applications like blockchains and for tasks such as securing
SSH connections. The Ed25519 algorithm used in uSECboot is implemented by
[monocypher](https://monocypher.org/). A slight modification to monocypher is
applied to create a smaller bootloader.

Images booted by uSECboot are prepended with a header that consists of TLV (tag
length value) items. Three vital TLV's are used to make the images secure:
1. A hash (sha256) of the firmware. Multiple hashes can be included, but the
first hash should always be of the firmware. When multiple hashes are included
all of them need to be valid.
2. A signed public key,
3. A signature calculated over the TLV's. This signature can be verified using
the provided signed public key. The signature is added as the last TLV of the
header.

Images are only allowed to boot when the signed public key is valid (it's
signature is OK), the signature is valid and the hash matches.

Other custom TLV's can be added to the image header, there is a reserved tag
range of 0x80 - 0xFE for custom tags.

## The signed public key
Each image for uSECboot is provided with a signed public key, what is it and why
is it added? The signed public key is a public key that is signed using what is
known as a root public key. This root public key is built into the bootloader.
This root public key is used to sign a new public key. This allows uSECboot to
verify that the provided public key in the signed public key TLV is created by a
trusted source as only a trusted source has access to the root public key.

Separating the public key that is used to sign a firmware from the root public
key (i.e. not signing the firmware with the root public key) has advantages:
1. As the root key is not used for signing images the chance of a leaked root
key is reduced,
2. It enables the creation of a set of public keys that are no longer trusted
and thus should no longer be accepted as valid public keys. uSECboot allows
verifying if a public keys is still trusted and does not accept any signatures
using rejected public keys.

## Tampering protection
uSECboot has incorporated (simple) tampering protection.

## Creating a basic bootloader using uSECboot
uSECboot is not a bootloader, it is a small library to create a secure
bootloader. Altough there are some provided bootloader implementation it is
encouraged to develop your custom secure bootloader that exactly fits your
needs.

The interface between the bootloader and uSECboot is setup by creating the
following structure for a "slot" that contains firmware:

```c
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
```

and providing the following routines:
```c
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
```

A bootloader is created by setting up the necessary slots and providing the
necessary routines. The `main` program of the bootloader should then only
contain some hardware initialization and a call to `usecboot_boot()`.

The `usecboot_boot()` routine will walk over the slots by requesting a slot
pointer using `usecboot_slot(idx)` where idx is an increasing number (starting
from 0). For this slot usecboot validates the public key tlv in the slot,
the header signature tlv in the slot and all hashes that are included included
in the header. If all validations check out usecboot will start the image by
issuing a call to `slot->api->boot(slot, ioff)`. If one of the validations
fail `usecboot_boot()` continues to the next slot. If no bootable image is found
it will spin endlessly.

The simplest bootloader setup would be one with only two slots, executable
from non volatile storage (e.g. flash). The first slot would contain the
firmware, while the second slot contains a updater or fallback firmware. The
`slot->api->read(slot, ...)` routine should read from the slot using a memcpy or
a mmap method. The `slot->api->boot(slot, ioff)` should boot the image located
at `ioff` from the header start.

## Extending the bootloader with extra functionality

The `usecboot_slot(idx)` routine that is provided by the port allows adding
extra functionality. As an example suppose a bootloader is created that has
two firmwares and an update firmware, at boot the "newest" version needs to
be selected. Such a setup requires the definition of 3 slots in the port. In the
`usecboot_slot(idx)` routine the headers of both firmwares can be read for a tlv
that contains the version (using `usecboot_tlv()`) when idx = 0. This allows
creating an index array of the order in which to try booting one of the images.
This index array is then used to supply the correct image slot.

Other possible uses of the `usecboot_slot(idx)` routine is to copy the from
flash image to ram (including or excluding the header) before starting any
evaluation of header or hashes. The `slot->api->read()` routine could do a
combination of reads from flash or ram depending on the requested read offset.

Another way to extend the functionality of the bootloader is by including
extra hashes in the image header. Suppose it is not wanted that a image can
just boot after being placed in the correct location, instead a image is only
allowed to boot after specific data has been written to the end of the image
slot (e.g. "boot_ready" is written at the end of the slot). The header can then
be extended with a hash of "boot_ready" at the end of the slot. As long as
"boot_ready" is not in place the image will not boot.

## Important remark

Although it is possible to use `usecboot_slot(idx)` for updating an image it is
advised not to do so. The updating mechanism that is provided by a thus created
bootloader would be missing out on future extensions (e.g. delta updates, ...)
as it could be difficult/impossible to update the bootloader. A better approach
is to use the fallback or updater image to provide the update functionality. It
is always possible to create a special update firmware to update the fallback or
updater image without loosing any of the secure boot features.




