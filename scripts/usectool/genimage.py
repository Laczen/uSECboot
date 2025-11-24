#!/usr/bin/env python3

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import struct
import click
import importlib.util
import sys
import os
from usectool.defines import *

def load_private_key(filename, password=None):
    with open(filename, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password.encode() if password else None
        )
    return private_key

def sha256_hash(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def load_user_script(script_path):
    """Load and validate user script"""
    if not os.path.exists(script_path):
        raise FileNotFoundError(f"User script not found: {script_path}")

    spec = importlib.util.spec_from_file_location("user_script", script_path)
    user_module = importlib.util.module_from_spec(spec)

    # Check if the required function exists
    if not hasattr(user_module, 'add_custom_tlvs'):
        raise AttributeError("User script must define 'add_custom_tlvs(header_data)' function")

    spec.loader.exec_module(user_module)
    return user_module

@click.command()
@click.argument('firmware', type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.option('--private-key', '-k', default='private_key.pem',
              help='Private key file for signing (default: private_key.pem)')
@click.option('--password', '-p', default=None,
              help='Password for private key (if encrypted)')
@click.option('--signed-key', '-s', default='signedpkey.bin',
              help='Signed public key file (default: signedpkey.bin)')
@click.option('--header-size', '-h', default=512,
              help='Header size in bytes (default: 512)')
@click.option('--user-script', '-u', default=None,
              help='Python script that adds custom TLVs before signing')
@click.option('--output', '-o', default=None,
              help='Output filename for signed firmware (default: {firmware}_signed.bin)')
def main(firmware, private_key, password, signed_key, header_size, user_script, output):
    """
    Generate signed firmware image using Ed25519 signature.

    FIRMWARE: Input firmware file to sign (required)
    """
    try:
        # Generate output filename if not specified
        if output is None:
            output = f"{firmware}_signed.bin"

        # Load private key
        click.echo(f"Loading private key from: {private_key}")
        key = load_private_key(private_key, password)

        # Read firmware
        click.echo(f"Reading firmware from: {firmware}")
        with open(firmware, 'rb') as f:
            firmware_data = f.read()

        # Calculate hash of firmware payload (excluding header)
        click.echo(f"Calculating SHA512 hash of firmware payload...")
        ihash = sha256_hash(firmware_data[header_size:])

        # Create hash TLV
        hashtlv_fmt = '> B B I I 32s'
        hashtlv_size = struct.calcsize(hashtlv_fmt)
        hashtlv = struct.pack(
            hashtlv_fmt,
            USECBOOT_HASH_TAG,
            hashtlv_size,
            header_size,
            len(firmware_data) - header_size,
            ihash
        )

        # Build initial header
        hdr = hashtlv

        # Add signed public key
        click.echo(f"Reading signed public key from: {signed_key}")
        with open(signed_key, 'rb') as f:
            signedpkey = f.read()
        hdr += signedpkey

        # Allow user script to add custom TLVs before signing
        if user_script:
            click.echo(f"Loading user script: {user_script}")
            user_module = load_user_script(user_script)
            click.echo("Executing user script to add custom TLVs...")
            hdr = user_module.add_custom_tlvs(hdr)
            click.echo(f"Header size after user script: {len(hdr)} bytes")

        # Sign the header (includes any custom TLVs added by user script)
        click.echo("Signing header...")
        signature = key.sign(hdr)

        # Create signature TLV
        sigtlv_fmt = '> B B I 64s'
        sigtlv_fmt_size = struct.calcsize(sigtlv_fmt)
        sigtlv = struct.pack(
            sigtlv_fmt,
            USECBOOT_SIGN_TAG,
            sigtlv_fmt_size,
            len(hdr),  # This includes any custom TLVs
            bytes(signature)
        )

        # Finalize header
        hdr += sigtlv

        # Combine header with firmware
        click.echo("Combining header with firmware...")
        data = bytearray(firmware_data)

        # Check if header fits in allocated space
        if len(hdr) > header_size:
            click.echo(f"⚠️ Warning: Header size ({len(hdr)} bytes) exceeds allocated header size ({header_size} bytes)")

        data[0:len(hdr)] = hdr

        # Write output
        click.echo(f"Writing signed firmware to: {output}")
        with open(output, 'wb') as f:
            f.write(data)

        click.echo("✓ Signed firmware generated successfully!")

    except FileNotFoundError as e:
        click.echo(f"❌ Error: File not found - {e}", err=True)
        raise click.Abort()
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        raise click.Abort()

if __name__ == '__main__':
    main()