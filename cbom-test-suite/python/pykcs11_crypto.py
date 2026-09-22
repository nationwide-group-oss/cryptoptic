"""
Test suite for PyKCS11.ql — PyKCS11 / PKCS#11 HSM library usage.
Each call site below should be detected by the query.
"""

import PyKCS11
from PyKCS11 import PyKCS11Lib, Mechanism
from PyKCS11 import CKM_AES_GCM, CKM_AES_CBC, CKM_AES_KEY_GEN
from PyKCS11 import CKM_RSA_PKCS, CKM_RSA_PKCS_KEY_PAIR_GEN
from PyKCS11 import CKM_SHA256, CKM_SHA512, CKM_SHA_1
from PyKCS11 import CKM_ECDSA, CKM_EC_KEY_PAIR_GEN
from PyKCS11 import CKM_AES_CBC_PAD, CKM_RSA_PKCS_OAEP

# =============================================================================
# Library initialisation
# =============================================================================

# PyKCS11Lib() — from direct import
lib = PyKCS11Lib()
lib.load("/usr/lib/softhsm/libsofthsm2.so")

# PyKCS11.PyKCS11Lib() — attribute access
lib2 = PyKCS11.PyKCS11Lib()

# Open session
slot = lib.getSlotList(tokenPresent=True)[0]
session = lib.openSession(slot)

# =============================================================================
# Mechanism constructor — primary algorithm carrier
# =============================================================================

# Using imported CKM_* constants (plain Name)
mech_aes_gcm = Mechanism(CKM_AES_GCM, None)
mech_aes_cbc = Mechanism(CKM_AES_CBC, b"\x00" * 16)
mech_rsa_pkcs = Mechanism(CKM_RSA_PKCS, None)
mech_sha256 = Mechanism(CKM_SHA256, None)
mech_ecdsa = Mechanism(CKM_ECDSA, None)

# Using PyKCS11.CKM_* (attribute access)
mech_sha512 = PyKCS11.Mechanism(PyKCS11.CKM_SHA512, None)
mech_rsa_oaep = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS_OAEP, None)

# =============================================================================
# Key generation
# =============================================================================

# generateKey — symmetric key generation
aes_key = session.generateKey(
    [
        ("CKA_CLASS", "CKO_SECRET_KEY"),
        ("CKA_KEY_TYPE", "CKK_AES"),
        ("CKA_VALUE_LEN", 32),
    ],
    Mechanism(CKM_AES_KEY_GEN, None),
)

# generateKeyPair — asymmetric key pair generation
pub_key, priv_key = session.generateKeyPair(
    [("CKA_KEY_TYPE", "CKK_RSA"), ("CKA_MODULUS_BITS", 2048)],
    [("CKA_KEY_TYPE", "CKK_RSA")],
    Mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, None),
)

# EC key pair generation
ec_pub, ec_priv = session.generateKeyPair(
    [("CKA_KEY_TYPE", "CKK_EC"), ("CKA_EC_PARAMS", "P-256")],
    [("CKA_KEY_TYPE", "CKK_EC")],
    Mechanism(CKM_EC_KEY_PAIR_GEN, None),
)

# =============================================================================
# Encryption / Decryption
# =============================================================================

# session.encrypt with inline mechanism
ciphertext = session.encrypt(aes_key, b"plaintext data", Mechanism(CKM_AES_GCM, None))

# session.decrypt
plaintext = session.decrypt(aes_key, ciphertext, Mechanism(CKM_AES_CBC, b"\x00" * 16))

# RSA encryption
rsa_ciphertext = session.encrypt(
    pub_key, b"message", Mechanism(CKM_RSA_PKCS_OAEP, None)
)

# =============================================================================
# Signing / Verification
# =============================================================================

# session.sign
signature = session.sign(priv_key, b"data to sign", Mechanism(CKM_RSA_PKCS, None))

# session.verify
is_valid = session.verify(
    pub_key, b"data to sign", signature, Mechanism(CKM_RSA_PKCS, None)
)

# ECDSA signing
ec_sig = session.sign(ec_priv, b"data", Mechanism(CKM_ECDSA, None))

# =============================================================================
# Digest (hash)
# =============================================================================

# session.digest
hash_result = session.digest(b"data to hash", Mechanism(CKM_SHA256, None))
hash_sha512 = session.digest(b"data to hash", Mechanism(CKM_SHA512, None))
hash_sha1 = session.digest(b"data", Mechanism(CKM_SHA_1, None))

# =============================================================================
# Key wrapping / unwrapping / derivation
# =============================================================================

# session.wrapKey
wrapped = session.wrapKey(aes_key, priv_key, Mechanism(CKM_AES_CBC_PAD, b"\x00" * 16))

# session.unwrapKey
unwrapped = session.unwrapKey(
    aes_key,
    wrapped,
    [("CKA_CLASS", "CKO_PRIVATE_KEY")],
    Mechanism(CKM_AES_CBC_PAD, b"\x00" * 16),
)

# session.deriveKey
derived = session.deriveKey(
    priv_key, [("CKA_KEY_TYPE", "CKK_AES")], Mechanism(CKM_ECDSA, None)
)

# =============================================================================
# Multi-part operations — Init/Update/Final
# =============================================================================

# Encrypt multi-part
session.encryptInit(aes_key, Mechanism(CKM_AES_CBC, b"\x00" * 16))
session.encryptUpdate(b"part1")
session.encryptUpdate(b"part2")
ct_final = session.encryptFinal()

# Decrypt multi-part
session.decryptInit(aes_key, Mechanism(CKM_AES_CBC, b"\x00" * 16))
session.decryptUpdate(ciphertext[:16])
session.decryptUpdate(ciphertext[16:])
pt_final = session.decryptFinal()

# Sign multi-part
session.signInit(priv_key, Mechanism(CKM_RSA_PKCS, None))
session.signUpdate(b"chunk1")
session.signUpdate(b"chunk2")
sig_final = session.signFinal()

# Verify multi-part
session.verifyInit(pub_key, Mechanism(CKM_RSA_PKCS, None))
session.verifyUpdate(b"chunk1")
session.verifyUpdate(b"chunk2")
session.verifyFinal(sig_final)

# Digest multi-part
session.digestInit(Mechanism(CKM_SHA256, None))
session.digestUpdate(b"chunk1")
session.digestUpdate(b"chunk2")
digest_final = session.digestFinal()

# =============================================================================
# Random operations
# =============================================================================

random_data = session.generateRandom(32)
session.seedRandom(b"entropy_seed_data")

# =============================================================================
# Specialized mechanism classes (PyKCS11 v1.5+)
# =============================================================================

from PyKCS11 import AES_GCM_Mechanism, RSAOAEPMechanism, RSA_PSS_Mechanism
from PyKCS11 import ECDH1_DERIVE_Mechanism, EDDSA_Mechanism, AES_CTR_Mechanism
from PyKCS11 import (
    CONCATENATE_BASE_AND_DATA_Mechanism,
    CONCATENATE_BASE_AND_KEY_Mechanism,
)
from PyKCS11 import CONCATENATE_DATA_AND_BASE_Mechanism, EXTRACT_KEY_FROM_KEY_Mechanism
from PyKCS11 import XOR_BASE_AND_DATA_Mechanism

aes_gcm_mech = AES_GCM_Mechanism(b"\x00" * 12, b"", 128)
rsa_oaep_mech = RSAOAEPMechanism()
rsa_pss_mech = RSA_PSS_Mechanism()
ecdh_mech = ECDH1_DERIVE_Mechanism(b"peer_public_key")
eddsa_mech = EDDSA_Mechanism()
aes_ctr_mech = AES_CTR_Mechanism(b"\x00" * 16)

# Key derivation mechanism constructors
concat_base_data = CONCATENATE_BASE_AND_DATA_Mechanism(b"extra_data")
concat_base_key = CONCATENATE_BASE_AND_KEY_Mechanism(aes_key)
concat_data_base = CONCATENATE_DATA_AND_BASE_Mechanism(b"prefix_data")
extract_key = EXTRACT_KEY_FROM_KEY_Mechanism(0)
xor_base_data = XOR_BASE_AND_DATA_Mechanism(b"\xff" * 32)

# =============================================================================
# DigestSession — multi-part digest with digestKey support
# =============================================================================

# session.digestSession(mecha) — returns DigestSession
ds = session.digestSession(Mechanism(CKM_SHA256, None))

# DigestSession.digestKey(handle) — C_DigestKey
ds.digestKey(aes_key)

# =============================================================================
# Mechanism via keyword arg
# =============================================================================

ciphertext_kw = session.encrypt(aes_key, b"data", mecha=Mechanism(CKM_AES_GCM, None))
