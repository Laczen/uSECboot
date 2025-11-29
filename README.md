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
1. A hash (sha256) of the firmware,
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

## Creating a bootloader using uSECboot
uSECboot is not a bootloader, it is a small library to create a secure
bootloader. Altough there are some provided bootloader implementation it is
encouraged to develop your custom secure bootloader that exactly fits your
needs.

The interface between the bootloader and uSECboot is setup by creating the
following structure for a "slot" that contains firmware:

```c
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
```





