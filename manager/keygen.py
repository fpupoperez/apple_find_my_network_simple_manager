"""P-224 keypair helpers matching macless-haystack's ``generate_keys.py``.

macless-haystack uses NIST P-224. The device broadcasts the 28-byte
x-coordinate of the public key as its "advertisement key"; the matching
28-byte private scalar is used by the container to decrypt location reports.
"""

import secrets
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

AdvertisementKeyLength = 28

# P-224 curve order n (private keys must live in [1, n-1]).
_P224_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D


def random_private_bytes():
    for _ in range(16):
        value = secrets.randbits(224)
        if 1 <= value < _P224_N:
            return value.to_bytes(AdvertisementKeyLength, "big")
    raise RuntimeError("could not generate a valid P-224 private scalar")


def derive_public_x(private_bytes):
    """Return the 28-byte public x-coordinate for a 28-byte private key."""
    private_int = int.from_bytes(private_bytes, "big") % _P224_N
    key = ec.derive_private_key(private_int, ec.SECP224R1(), default_backend())
    return key.public_key().public_numbers().x.to_bytes(AdvertisementKeyLength, "big")


def generate_keypair():
    """Return (private_bytes, advertisement_bytes) in the macless-haystack layout."""
    private_bytes = random_private_bytes()
    return private_bytes, derive_public_x(private_bytes)


def private_key_to_pem(private_bytes):
    """PEM-encoded SEC1 private key, for OpenHaystack-compatible tooling."""
    private_int = int.from_bytes(private_bytes, "big")
    key = ec.derive_private_key(private_int, ec.SECP224R1(), default_backend())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def hex_to_bytes(value, label="key"):
    """Parse an un-prefixed hex string into 28 bytes, raising ValueError otherwise."""
    value = (value or "").strip().lower()
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("{} is not valid hexadecimal".format(label)) from exc
    if len(raw) != AdvertisementKeyLength:
        raise ValueError(
            "{} must be exactly {} bytes (got {} hex characters)".format(
                label, AdvertisementKeyLength, len(value)))
    return raw


def validate_keypair(private_hex, public_hex):
    """Raise ValueError if the pair does not correspond to the same P-224 keypair."""
    private_bytes = hex_to_bytes(private_hex, "private key")
    public_bytes = hex_to_bytes(public_hex, "advertisement key")
    derived = derive_public_x(private_bytes)
    if derived != public_bytes:
        raise ValueError(
            "advertisement key does not match the private key: derived "
            "{} from the private key".format(derived.hex()))
    return True


def macless_keyfile_bytes(device):
    """The raw ``*_keyfile`` binary block generate_keys.py writes (1 byte count + keys)."""
    payload = struct.pack("B", 1) + device.advertisement_key
    return payload