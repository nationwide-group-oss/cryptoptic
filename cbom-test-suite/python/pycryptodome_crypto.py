"""
Test suite for PyCryptodome.ql — PyCryptodome/PyCrypto library usage.
Each call site below should be detected by the query.
"""

from Crypto.Cipher import (
    AES,
    DES,
    DES3,
    Blowfish,
    ARC4,
    ChaCha20,
    Salsa20,
    ChaCha20_Poly1305,
)
from Crypto.Hash import (
    SHA256,
    SHA1,
    SHA384,
    SHA512,
    MD5,
    SHA3_256,
    BLAKE2b,
    RIPEMD160,
    HMAC,
    CMAC,
)
from Crypto.PublicKey import RSA, DSA, ECC, ElGamal
from Crypto.Signature import pkcs1_15, pss, DSS, eddsa, PKCS1_v1_5, PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2, scrypt, HKDF
from Crypto.Random import get_random_bytes

# =============================================================================
# Cipher — AES with various modes
# =============================================================================
key = get_random_bytes(32)
nonce = get_random_bytes(12)
iv = get_random_bytes(16)

cipher_gcm = AES.new(key, AES.MODE_GCM, nonce=nonce)
cipher_cbc = AES.new(key, AES.MODE_CBC, iv=iv)
cipher_ctr = AES.new(key, AES.MODE_CTR, nonce=nonce)
cipher_ecb = AES.new(key, AES.MODE_ECB)
cipher_cfb = AES.new(key, AES.MODE_CFB, iv=iv)
cipher_ofb = AES.new(key, AES.MODE_OFB, iv=iv)
cipher_ccm = AES.new(key, AES.MODE_CCM, nonce=nonce)
cipher_eax = AES.new(key, AES.MODE_EAX, nonce=nonce)
cipher_siv = AES.new(key, AES.MODE_SIV, nonce=nonce)
cipher_ocb = AES.new(key, AES.MODE_OCB, nonce=nonce)

# =============================================================================
# Cipher — DES, 3DES, Blowfish
# =============================================================================
des_key = get_random_bytes(8)
des3_key = get_random_bytes(24)
bf_key = get_random_bytes(16)

cipher_des = DES.new(des_key, DES.MODE_CBC, iv=get_random_bytes(8))
cipher_3des = DES3.new(des3_key, DES3.MODE_CBC, iv=get_random_bytes(8))
cipher_bf = Blowfish.new(bf_key, Blowfish.MODE_CBC, iv=get_random_bytes(8))

# =============================================================================
# Cipher — Stream ciphers
# =============================================================================
cipher_rc4 = ARC4.new(key)
cipher_chacha = ChaCha20.new(key=key, nonce=get_random_bytes(8))
cipher_salsa = Salsa20.new(key=key, nonce=get_random_bytes(8))
cipher_cc20p = ChaCha20_Poly1305.new(key=key, nonce=nonce)

# =============================================================================
# Hash modules
# =============================================================================
h_sha256 = SHA256.new(b"data")
h_sha1 = SHA1.new(b"data")
h_sha384 = SHA384.new(b"data")
h_sha512 = SHA512.new(b"data")
h_md5 = MD5.new(b"data")
h_sha3 = SHA3_256.new(b"data")
h_blake2b = BLAKE2b.new(digest_bytes=32, data=b"data")
h_ripemd = RIPEMD160.new(b"data")

# =============================================================================
# HMAC
# =============================================================================
h_hmac = HMAC.new(b"key", b"msg", SHA256)

# =============================================================================
# CMAC
# =============================================================================
c_cmac = CMAC.new(key, ciphermod=AES)

# =============================================================================
# PublicKey
# =============================================================================
rsa_key = RSA.generate(2048)
rsa_imported = RSA.import_key(open("key.pem").read())
dsa_key = DSA.generate(2048)
ecc_key = ECC.generate(curve="P-256")
ecc_key2 = ECC.generate(curve="Ed25519")

# =============================================================================
# Signature
# =============================================================================
signer_pkcs1 = pkcs1_15.new(rsa_key)
signer_pss = pss.new(rsa_key)
signer_dss = DSS.new(ecc_key, "fips-186-3")
signer_eddsa = eddsa.new(ecc_key2, "rfc8032")

# RSA encryption
cipher_oaep = PKCS1_OAEP.new(rsa_key)

# =============================================================================
# KDF
# =============================================================================
derived_pbkdf2 = PBKDF2(b"password", b"salt", dkLen=32, count=100000)
derived_scrypt = scrypt(b"password", b"salt", 32, N=2**14, r=8, p=1)
derived_hkdf = HKDF(b"input_key", 32, b"salt", SHA256)

# =============================================================================
# Random
# =============================================================================
rand_bytes = get_random_bytes(32)

# =============================================================================
# Padding
# =============================================================================
from Crypto.Util.Padding import pad, unpad

padded_data = pad(b"short", AES.block_size)
unpadded_data = unpad(padded_data, AES.block_size)

# =============================================================================
# Counter
# =============================================================================
from Crypto.Util.Counter import new as counter_new

ctr = counter_new(128)

# =============================================================================
# Shamir Secret Sharing
# =============================================================================
from Crypto.Protocol.SecretSharing import Shamir

shares = Shamir.split(2, 5, b"\x00" * 16)
recovered = Shamir.combine(shares[:2])

# =============================================================================
# Number Theory Utilities
# =============================================================================
from Crypto.Util.number import getPrime, isPrime, getStrongPrime

prime = getPrime(2048)
is_prime = isPrime(prime)
strong_prime = getStrongPrime(2048)

# =============================================================================
# PEM / PKCS8
# =============================================================================
from Crypto.IO import PEM, PKCS8

pem_encoded = PEM.encode(b"der_data", "RSA PRIVATE KEY")
pem_decoded = PEM.decode(pem_encoded)
pkcs8_wrapped = PKCS8.wrap(b"key_data", "1.2.840.113549.1.1.1")

# =============================================================================
# KMAC / TupleHash (newer PyCryptodome)
# =============================================================================
from Crypto.Hash import KMAC128, KMAC256, TupleHash128, TupleHash256

h_kmac128 = KMAC128.new(key=b"key", data=b"data", mac_len=32)
h_kmac256 = KMAC256.new(key=b"key", data=b"data", mac_len=64)
h_tuple128 = TupleHash128.new(digest_bytes=32)
h_tuple256 = TupleHash256.new(digest_bytes=64)

# =============================================================================
# DSA — construct and importKey
# =============================================================================
dsa_constructed = DSA.construct((0, 0, 0, 0, 0))
dsa_imported2 = DSA.importKey(open("dsa_key.pem").read())

# =============================================================================
# KDF — bcrypt_check, SP800_108_Counter, HKDF direct
# =============================================================================
from Crypto.Protocol.KDF import bcrypt_check, SP800_108_Counter, HKDF as pcd_hkdf

bcrypt_ok = bcrypt_check(b"password", b"$2a$12$...")
sp800_key = SP800_108_Counter(b"master", 32, prf=None)
hkdf_key = pcd_hkdf(b"input", 32, b"salt", SHA256)
