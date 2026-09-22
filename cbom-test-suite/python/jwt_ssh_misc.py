"""
Test suite for JwtSshMisc.ql — JWT, SSH, NaCl, GPG, and misc crypto usage.
Each call site below should be detected by the query.
"""

import jwt
from jose import jwt as jose_jwt, jws, jwe
import nacl.secret
import nacl.public
import nacl.signing
import nacl.utils
import paramiko
import gnupg
import rsa
from ecdsa import SigningKey, NIST256p, SECP256k1
from itsdangerous import URLSafeTimedSerializer, URLSafeSerializer, Signer

# =============================================================================
# PyJWT
# =============================================================================
token_hs256 = jwt.encode({"sub": "1234"}, "secret", algorithm="HS256")
token_rs256 = jwt.encode({"sub": "1234"}, "private_key", algorithm="RS256")
token_es256 = jwt.encode({"sub": "1234"}, "private_key", algorithm="ES256")
token_default = jwt.encode({"sub": "1234"}, "secret")  # default HS256
decoded = jwt.decode(token_hs256, "secret", algorithms=["HS256"])

# =============================================================================
# python-jose
# =============================================================================
jose_token = jose_jwt.encode({"sub": "1234"}, "secret", algorithm="HS256")
jose_decoded = jose_jwt.decode(jose_token, "secret", algorithms=["HS256"])
jws_signed = jws.sign({"data": "test"}, "secret", algorithm="HS256")
jws_valid = jws.verify(jws_signed, "secret", algorithms=["HS256"])
jwe_encrypted = jwe.encrypt(b"plaintext", "public_key", algorithm="RSA-OAEP")
jwe_decrypted = jwe.decrypt(jwe_encrypted, "private_key")

# python-jose — additional methods
jws_header = jws.get_unverified_header(jws_signed)
jws_headers = jws.get_unverified_headers(jws_signed)
jwe_header = jwe.get_unverified_header(jwe_encrypted)

from jose import jwk

jose_key = jwk.construct("secret", algorithm="HS256")

# =============================================================================
# PyNaCl
# =============================================================================

# SecretBox (XSalsa20-Poly1305)
secret_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
box = nacl.secret.SecretBox(secret_key)

# Box (X25519+XSalsa20-Poly1305)
sk = nacl.public.PrivateKey.generate()
pk = sk.public_key
pub_box = nacl.public.Box(sk, pk)

# SealedBox
sealed = nacl.public.SealedBox(pk)

# SigningKey (Ed25519)
signing_key = nacl.signing.SigningKey.generate()
verify_key = nacl.signing.VerifyKey(signing_key.verify_key.encode())

# nacl.hash — siphash24 / siphashx24
import nacl.hash
from nacl.pwhash import argon2id, argon2i
from nacl.pwhash import scrypt as pwhash_scrypt  # aliased to avoid name clash
from nacl import pwhash

siphash_result = nacl.hash.siphash24(b"message", key=b"0123456789abcdef")
siphashx_result = nacl.hash.siphashx24(b"message", key=b"0123456789abcdef")

# nacl.pwhash — top-level str/verify
pw_hash = pwhash.str(b"my-password")
pw_valid = pwhash.verify(pw_hash, b"my-password")

# nacl.pwhash per-mechanism — argon2id
salt = nacl.utils.random(argon2id.SALTBYTES)
argon2id_key = argon2id.kdf(32, b"password", salt)
argon2id_hash = argon2id.str(b"password")
argon2id_valid = argon2id.verify(argon2id_hash, b"password")

# nacl.pwhash per-mechanism — argon2i
salt_i = nacl.utils.random(argon2i.SALTBYTES)
argon2i_key = argon2i.kdf(32, b"password", salt_i)
argon2i_hash = argon2i.str(b"password")
argon2i_valid = argon2i.verify(argon2i_hash, b"password")

# nacl.pwhash per-mechanism — scrypt (receiver name must be "scrypt" for CodeQL match)
# In real code: from nacl.pwhash import scrypt; scrypt.kdf(...)
scrypt = pwhash_scrypt
salt_s = nacl.utils.random(scrypt.SALTBYTES)
scrypt_key = scrypt.kdf(32, b"password", salt_s)
scrypt_hash = scrypt.str(b"password")
scrypt_valid = scrypt.verify(scrypt_hash, b"password")

# Box.shared_key()
shared_secret = pub_box.shared_key()

# nacl.utils.randombytes_deterministic()
deterministic_bytes = nacl.utils.randombytes_deterministic(32, seed=b"0" * 32)

# =============================================================================
# paramiko — SSH
# =============================================================================
client = paramiko.SSHClient()
transport = paramiko.Transport(("hostname", 22))
rsa_ssh_key = paramiko.RSAKey.generate(2048)
ecdsa_ssh_key = paramiko.ECDSAKey.generate()
ed25519_ssh_key = paramiko.Ed25519Key.generate()
dss_ssh_key = paramiko.DSSKey.generate()
sftp_client = paramiko.SFTPClient.from_transport(transport)
agent = paramiko.Agent()

# =============================================================================
# python-gnupg
# =============================================================================
gpg = gnupg.GPG()
encrypted = gpg.encrypt("data", "recipient@example.com")
decrypted = gpg.decrypt(str(encrypted))
signed = gpg.sign("data")
verified = gpg.verify(str(signed))

# =============================================================================
# python-rsa
# =============================================================================
pub_rsa, priv_rsa = rsa.newkeys(2048)
rsa_encrypted = rsa.encrypt(b"message", pub_rsa)
rsa_decrypted = rsa.decrypt(rsa_encrypted, priv_rsa)
rsa_signature = rsa.sign(b"message", priv_rsa, "SHA-256")
rsa_verified = rsa.verify(b"message", rsa_signature, pub_rsa)

# =============================================================================
# python-ecdsa
# =============================================================================
ecdsa_key_p256 = SigningKey.generate(curve=NIST256p)
ecdsa_key_k256 = SigningKey.generate(curve=SECP256k1)

# =============================================================================
# itsdangerous
# =============================================================================
safe_serializer = URLSafeTimedSerializer("secret-key")
safe_ser2 = URLSafeSerializer("secret-key")
signer = Signer("secret-key")

# itsdangerous — additional methods
data_unsafe = safe_serializer.loads_unsafe(signed_data)
data_unsafe2 = safe_serializer.load_unsafe(file_obj)
key = signer.derive_key()
sig = signer.get_signature("value")

# itsdangerous — NoneAlgorithm (insecure, no-op signing)
from itsdangerous import NoneAlgorithm

none_algo = NoneAlgorithm()

# =============================================================================
# Web3 / Ethereum
# =============================================================================
from eth_account import Account

acct = Account.create()
signed_msg = Account.sign_message(message, private_key)
signed_tx = Account.sign_transaction(tx, private_key)
recovered = Account.recover_message(message, signature=signed_msg)
acct_from_key = Account.from_key(private_key)

# =============================================================================
# PyJWT — get_unverified_header
# =============================================================================
header = jwt.get_unverified_header(token_hs256)

# =============================================================================
# PyJWT — algorithm classes
# =============================================================================
from jwt.algorithms import (
    RSAAlgorithm,
    ECAlgorithm,
    HMACAlgorithm,
    Ed25519Algorithm,
    Ed448Algorithm,
    OKPAlgorithm,
    RSAPSSAlgorithm,
)

rsa_algo = RSAAlgorithm(RSAAlgorithm.SHA256)
ec_algo = ECAlgorithm(ECAlgorithm.SHA256)
hmac_algo = HMACAlgorithm(HMACAlgorithm.SHA256)
ed25519_algo = Ed25519Algorithm()
ed448_algo = Ed448Algorithm()
okp_algo = OKPAlgorithm()
rsapss_algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)

# =============================================================================
# PyJWS — constructor and instance methods
# =============================================================================
from jwt import PyJWS

pyjws = PyJWS()
pyjws_encoded = pyjws.encode(b"payload", "secret", algorithm="HS256")
pyjws_decoded = pyjws.decode(pyjws_encoded, "secret", algorithms=["HS256"])

# =============================================================================
# pyOpenSSL — SSL Context methods
# =============================================================================
from OpenSSL import SSL

ctx = SSL.Context(SSL.TLSv1_2_METHOD)
ctx.set_cipher_list(b"HIGH:!aNULL:!MD5")
ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
ctx.set_verify(SSL.VERIFY_PEER, callback)

# =============================================================================
# paramiko — get_security_options
# =============================================================================
transport2 = paramiko.Transport(("hostname", 22))
sec_opts = transport2.get_security_options()
