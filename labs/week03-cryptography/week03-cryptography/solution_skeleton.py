import os
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher, Type
from Crypto.Cipher import AES

ph = PasswordHasher(type=Type.ID)

def store_password(pw: str) -> str:
    """Store a new password using Argon2id."""
    return ph.hash(pw)


def verify_password(hash_: str, pw: str) -> bool:
    """Verify an Argon2id password."""
    try:
        return ph.verify(hash_, pw)
    except Exception:
        return False


def is_legacy_md5(stored_hash: str) -> bool:
    """Detect an old 32-character MD5 password hash."""
    if len(stored_hash) != 32:
        return False

    try:
        int(stored_hash, 16)
        return True
    except ValueError:
        return False


def verify_and_rehash(stored_hash: str, pw: str) -> tuple[bool, str]:
    """
    Verify a password and migrate legacy MD5 to Argon2id.

    Returns:
        (login_successful, resulting_hash)
    """

    if is_legacy_md5(stored_hash):
        candidate_md5 = hashlib.md5(pw.encode()).hexdigest()

        if hmac.compare_digest(candidate_md5, stored_hash):
            # Correct legacy password -> immediately upgrade it.
            new_hash = store_password(pw)
            return True, new_hash

        return False, stored_hash

    try:
        if ph.verify(stored_hash, pw):

            # Upgrade parameters later if Argon2 settings change.
            if ph.check_needs_rehash(stored_hash):
                return True, store_password(pw)

            return True, stored_hash

    except Exception:
        pass

    return False, stored_hash

def encrypt_gcm(
    data: bytes,
    key: bytes
) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt using AES-GCM.

    Returns:
        nonce, ciphertext, authentication tag
    """

    nonce = os.urandom(12)

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    ciphertext, tag = cipher.encrypt_and_digest(data)

    return nonce, ciphertext, tag


def decrypt_gcm(
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    key: bytes
) -> bytes:
    """
    Decrypt AES-GCM and verify the authentication tag.
    Raises ValueError if ciphertext/tag was modified.
    """

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    return cipher.decrypt_and_verify(ciphertext, tag)

def reset_token() -> str:
    """Generate an unpredictable security token."""
    return secrets.token_urlsafe(16)

if __name__ == "__main__":

    print("=== Argon2id Password Storage ===")

    password = "password123"

    password_hash = store_password(password)

    print("Hash:", password_hash)
    print(
        "Argon2 verify:",
        verify_password(password_hash, password)
    )

    print("\n=== Rehash-on-Login Migration ===")

    legacy_md5 = hashlib.md5(
        password.encode()
    ).hexdigest()

    print("Before (MD5):", legacy_md5)

    login_ok, migrated_hash = verify_and_rehash(
        legacy_md5,
        password
    )

    print("Login successful:", login_ok)
    print("After:", migrated_hash)

    print(
        "Migrated to Argon2id:",
        migrated_hash.startswith("$argon2id$")
    )

    print("\n=== Encryption Key ===")
    key_hex = os.environ.get("ENC_KEY_HEX")

    if key_hex:
        key = bytes.fromhex(key_hex)
        print("\nEncryption key source: ENC_KEY_HEX")
    else:
        key = os.urandom(32)
        print(
            "\nEncryption key source: temporary random "
            "demo key (set ENC_KEY_HEX in production)"
        )

    print("\n=== AES-GCM Round Trip ===")

    message = b"secret"

    nonce, ciphertext, tag = encrypt_gcm(
        message,
        key
    )

    print("Nonce:", nonce.hex())
    print("Nonce length:", len(nonce), "bytes")
    print("Ciphertext:", ciphertext.hex())
    print("Tag:", tag.hex())

    decrypted = decrypt_gcm(
        nonce,
        ciphertext,
        tag,
        key
    )

    print("Decrypted:", decrypted.decode())
    print(
        "Round trip successful:",
        decrypted == message
    )

    print("\n=== AES-GCM Tamper Test ===")

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1

    try:
        decrypt_gcm(
            nonce,
            bytes(tampered),
            tag,
            key
        )

        print("Tamper detected: False")

    except ValueError:
        print(
            "Tamper detected: True "
            "(authentication failed)"
        )

    print("\n=== Secure Reset Token ===")

    token = reset_token()
    print("Token:", token)