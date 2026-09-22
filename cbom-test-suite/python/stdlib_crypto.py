"""
Test suite for StdlibCrypto.ql — Python standard library crypto usage.
Each call site below should be detected by the query.
"""

import hashlib
import hmac
import secrets
import os
import ssl

# =============================================================================
# hashlib — Direct hash constructors
# =============================================================================
md5_hash = hashlib.md5(b"data")
sha1_hash = hashlib.sha1(b"data")
sha224_hash = hashlib.sha224(b"data")
sha256_hash = hashlib.sha256(b"data")
sha384_hash = hashlib.sha384(b"data")
sha512_hash = hashlib.sha512(b"data")

# SHA-3 family
sha3_224_hash = hashlib.sha3_224(b"data")
sha3_256_hash = hashlib.sha3_256(b"data")
sha3_384_hash = hashlib.sha3_384(b"data")
sha3_512_hash = hashlib.sha3_512(b"data")

# BLAKE2
blake2b_hash = hashlib.blake2b(b"data")
blake2s_hash = hashlib.blake2s(b"data")

# SHAKE
shake128 = hashlib.shake_128(b"data")
shake256 = hashlib.shake_256(b"data")

# =============================================================================
# hashlib.new() — String-based constructors
# =============================================================================
h1 = hashlib.new("md5", b"data")
h2 = hashlib.new("sha256", b"data")
h3 = hashlib.new("sha3_256", b"data")
h4 = hashlib.new("blake2b", b"data")
h5 = hashlib.new("ripemd160", b"data")
h6 = hashlib.new("whirlpool", b"data")
h7 = hashlib.new("sm3", b"data")

# =============================================================================
# hashlib.pbkdf2_hmac
# =============================================================================
dk = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 100000)
dk2 = hashlib.pbkdf2_hmac("sha512", b"password", b"salt", 100000)

# =============================================================================
# hashlib.file_digest (Python 3.11+)
# =============================================================================
with open("file.txt", "rb") as f:
    digest = hashlib.file_digest(f, "sha256")

# =============================================================================
# hmac — with various digestmod forms
# =============================================================================

# Keyword: Attribute reference
h_hmac1 = hmac.new(b"key", b"msg", digestmod=hashlib.sha256)

# Keyword: string
h_hmac2 = hmac.new(b"key", b"msg", digestmod="sha256")

# Positional: Attribute reference
h_hmac3 = hmac.new(b"key", b"msg", hashlib.sha256)

# One-shot digest (Python 3.8+)
h_hmac4 = hmac.digest(b"key", b"msg", digest="sha256")

# compare_digest
is_equal = hmac.compare_digest(b"a", b"b")

# =============================================================================
# secrets — CSPRNG
# =============================================================================
token1 = secrets.token_bytes(32)
token2 = secrets.token_hex(32)
token3 = secrets.token_urlsafe(32)

# =============================================================================
# os.urandom
# =============================================================================
random_bytes = os.urandom(32)

# =============================================================================
# ssl — TLS
# =============================================================================
ctx1 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx2 = ssl.create_default_context()
ctx1.load_cert_chain("cert.pem", "key.pem")
ctx1.set_ciphers("TLS_AES_256_GCM_SHA384")
ctx1.load_verify_locations(cafile="ca-bundle.crt")
ctx1.set_alpn_protocols(["h2", "http/1.1"])

# =============================================================================
# ssl — Utility functions
# =============================================================================
ssl.get_default_verify_paths()
ssl.enum_certificates("CA")
ssl.enum_crls("CA")
ssl.match_hostname(cert_dict, "example.com")
ssl.cert_time_to_seconds("May  9 00:00:00 2024 GMT")
ssl.get_server_certificate(("example.com", 443))
ssl.DER_cert_to_PEM_cert(der_data)
ssl.PEM_cert_to_DER_cert(pem_data)

# =============================================================================
# crypt — Unix password hashing (deprecated in 3.13)
# =============================================================================
import crypt

crypt_hash = crypt.crypt("password")
crypt_salt = crypt.mksalt(crypt.METHOD_SHA512)
