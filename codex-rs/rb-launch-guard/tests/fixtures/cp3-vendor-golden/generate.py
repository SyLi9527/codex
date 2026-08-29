#!/usr/bin/env python3
"""Reproduce the CP3 vendor-offer golden without Rust implementation code.

Run from any directory:
  python3 codex-rs/rb-launch-guard/tests/fixtures/cp3-vendor-golden/generate.py

Python's standard library performs only canonical framing, hashing, and
base64url encoding. OpenSSL performs public-key derivation and Ed25519 signing.
This script is an offline review fixture and is not part of a Cargo or Bazel
target.
"""

import base64
import hashlib
import pathlib
import struct
import subprocess
import tempfile

ROOT_PRIVATE_KEY = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g
-----END PRIVATE KEY-----
"""
RELEASE_PRIVATE_KEY = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJ
-----END PRIVATE KEY-----
"""

BUNDLE_MAGIC = b"RBVO1\0"
MANIFEST_DOMAIN = b"rb.vendor-manifest.v1\0"
RELEASE_DOMAIN = b"rb.vendor-release.v1\0"
KEY_ID_DOMAIN = b"rb.vendor-release-key-id.v1\0ed25519\0"
NOT_BEFORE = b"2026-08-28T00:00:00Z"
EXPIRES = b"2026-08-29T00:00:00Z"
EXPECTED_CARRIER_SHA256 = "c3efbc77e60cb9b7a798be5a815cb4c09349b286f0098bcada5d055eada4fd6c"


def run(*args: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        args,
        input=input_bytes,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def public_key(private_key_path: pathlib.Path) -> bytes:
    der = run(
        "openssl",
        "pkey",
        "-in",
        str(private_key_path),
        "-pubout",
        "-outform",
        "DER",
    )
    if len(der) != 44:
        raise RuntimeError(f"unexpected Ed25519 SubjectPublicKeyInfo length: {len(der)}")
    return der[-32:]


def key_id(public: bytes) -> bytes:
    return hashlib.sha256(KEY_ID_DOMAIN + public).digest()


def sign_object(domain: bytes, body: bytes, private_key_path: pathlib.Path) -> bytes:
    framed = domain + struct.pack(">Q", len(body)) + body
    with tempfile.NamedTemporaryFile() as message_file:
        message_file.write(framed)
        message_file.flush()
        signature = run(
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_key_path),
            "-in",
            message_file.name,
        )
    if len(signature) != 64:
        raise RuntimeError(f"unexpected Ed25519 signature length: {len(signature)}")
    return framed + signature


def object_digest(domain: bytes, body: bytes) -> bytes:
    return hashlib.sha256(domain + struct.pack(">Q", len(body)) + body).digest()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="cp3-vendor-golden-") as temp_dir:
        temp = pathlib.Path(temp_dir)
        root_key_path = temp / "root.pem"
        release_key_path = temp / "release.pem"
        root_key_path.write_bytes(ROOT_PRIVATE_KEY)
        release_key_path.write_bytes(RELEASE_PRIVATE_KEY)

        root_public = public_key(root_key_path)
        release_public = public_key(release_key_path)
        certificate = (
            b"\x01"
            + release_public
            + key_id(release_public)
            + b"\x01"
            + struct.pack(">Q", 1)
            + struct.pack(">Q", 100)
            + NOT_BEFORE
            + EXPIRES
        )
        manifest_body = (
            b"MAN1"
            + struct.pack(">Q", 1)
            + bytes(32)
            + key_id(root_public)
            + b"\x01"
            + struct.pack(">H", len(certificate))
            + certificate
            + b"\x00"
            + b"\x00"
        )
        manifest = sign_object(MANIFEST_DOMAIN, manifest_body, root_key_path)

        release_body = (
            b"REL1"
            + struct.pack(">Q", 1)
            + bytes(32)
            + object_digest(MANIFEST_DOMAIN, manifest_body)
            + key_id(release_public)
            + hashlib.sha256(certificate).digest()
            + NOT_BEFORE
            + EXPIRES
            + b"\x07"
            + b"".join(
                bytes([role]) + bytes([10 + role]) * 32 for role in range(1, 8)
            )
        )
        release = sign_object(RELEASE_DOMAIN, release_body, release_key_path)
        bundle = (
            BUNDLE_MAGIC
            + b"\x01"
            + struct.pack(">I", len(manifest))
            + manifest
            + struct.pack(">I", len(release))
            + release
        )
        carrier = base64.urlsafe_b64encode(bundle).rstrip(b"=").decode("ascii")
        carrier_sha256 = hashlib.sha256(bundle).hexdigest()
        if carrier_sha256 != EXPECTED_CARRIER_SHA256:
            raise RuntimeError(
                f"golden mismatch: expected {EXPECTED_CARRIER_SHA256}, got {carrier_sha256}"
            )

        print(run("openssl", "version").decode("ascii").strip())
        print(f"root_private_key_sha256={hashlib.sha256(ROOT_PRIVATE_KEY).hexdigest()}")
        print(f"release_private_key_sha256={hashlib.sha256(RELEASE_PRIVATE_KEY).hexdigest()}")
        print(f"decoded_bundle_sha256={carrier_sha256}")
        print(f"carrier={carrier}")


if __name__ == "__main__":
    main()
