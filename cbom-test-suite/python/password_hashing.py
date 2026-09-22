"""
Test suite for PasswordHashing.ql — password hashing library usage.
Each call site below should be detected by the query.
"""

import bcrypt
import argon2
from argon2 import PasswordHasher
from passlib.hash import bcrypt as passlib_bcrypt, argon2 as passlib_argon2
from passlib.hash import pbkdf2_sha256, pbkdf2_sha512, sha256_crypt, sha512_crypt
from passlib.hash import scrypt as passlib_scrypt
from passlib.hash import pbkdf2_sha1
from passlib.hash import md5_crypt, des_crypt
from passlib.hash import ldap_sha256_crypt, ldap_sha512_crypt, ldap_bcrypt
from passlib.hash import ldap_pbkdf2_sha256, ldap_pbkdf2_sha512
from passlib.hash import (
    django_pbkdf2_sha256,
    django_pbkdf2_sha1,
    django_bcrypt,
    django_argon2,
)
from passlib.hash import phpass, mysql_sha1, mysql323
from passlib.hash import oracle10g, oracle11, postgres_md5
from passlib.hash import mssql2000, mssql2005
from passlib.hash import nthash, lmhash
from passlib.hash import cisco_type7, fshp
from passlib.hash import hex_sha256, hex_sha512, plaintext
from passlib.context import CryptContext
import hashlib

# =============================================================================
# bcrypt
# =============================================================================
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(b"password", salt)
is_valid = bcrypt.checkpw(b"password", hashed)
derived = bcrypt.kdf(
    password=b"password", salt=b"salt", desired_key_bytes=32, rounds=100
)

# =============================================================================
# argon2-cffi
# =============================================================================
ph = argon2.PasswordHasher()
ph2 = PasswordHasher()
a2_hash = ph.hash("password")
a2_valid = ph.verify(a2_hash, "password")

# argon2-cffi low-level
from argon2.low_level import hash_secret, hash_secret_raw, verify_secret, Type

low_hash = hash_secret(
    b"secret",
    b"salt",
    time_cost=1,
    memory_cost=8,
    parallelism=1,
    hash_len=32,
    type=Type.ID,
)
low_raw = hash_secret_raw(
    b"secret",
    b"salt",
    time_cost=1,
    memory_cost=8,
    parallelism=1,
    hash_len=32,
    type=Type.ID,
)
low_verify = verify_secret(low_hash, b"secret", type=Type.ID)

# argon2-cffi deprecated module-level APIs
dep_hash = argon2.hash_password(b"password")
dep_raw = argon2.hash_password_raw(b"password")
dep_verify = argon2.verify_password(dep_hash, b"password")

# =============================================================================
# passlib
# =============================================================================
p_hash1 = passlib_bcrypt.hash("password")
p_valid1 = passlib_bcrypt.verify("password", p_hash1)

p_hash2 = passlib_argon2.hash("password")
p_valid2 = passlib_argon2.verify("password", p_hash2)

p_hash3 = pbkdf2_sha256.hash("password")
p_valid3 = pbkdf2_sha256.verify("password", p_hash3)

p_hash4 = pbkdf2_sha512.hash("password")
p_hash5 = sha256_crypt.hash("password")
p_hash6 = sha512_crypt.hash("password")
p_hash7 = passlib_scrypt.hash("password")

# passlib — pbkdf2_sha1
p_hash8 = pbkdf2_sha1.hash("password")

# passlib — md5_crypt / des_crypt (legacy Unix)
p_hash9 = md5_crypt.hash("password")
p_hash10 = des_crypt.hash("password")

# passlib — LDAP schemes
p_hash11 = ldap_sha256_crypt.hash("password")
p_hash12 = ldap_sha512_crypt.hash("password")
p_hash13 = ldap_bcrypt.hash("password")
p_hash14 = ldap_pbkdf2_sha256.hash("password")
p_hash15 = ldap_pbkdf2_sha512.hash("password")

# passlib — Django schemes
p_hash16 = django_pbkdf2_sha256.hash("password")
p_hash17 = django_pbkdf2_sha1.hash("password")
p_hash18 = django_bcrypt.hash("password")
p_hash19 = django_argon2.hash("password")

# passlib — Application-specific schemes
p_hash20 = phpass.hash("password")
p_hash21 = mysql_sha1.hash("password")
p_hash22 = mysql323.hash("password")
p_hash23 = oracle10g.hash("password", user="SYSTEM")
p_hash24 = oracle11.hash("password")
p_hash25 = postgres_md5.hash("password", user="postgres")
p_hash26 = mssql2000.hash("password")
p_hash27 = mssql2005.hash("password")

# passlib — Windows hashes
p_hash28 = nthash.hash("password")
p_hash29 = lmhash.hash("password")

# passlib — Misc schemes
p_hash30 = cisco_type7.hash("password")
p_hash31 = fshp.hash("password")
p_hash32 = hex_sha256.hash("password")
p_hash33 = hex_sha512.hash("password")
p_hash34 = plaintext.hash("password")

# passlib CryptContext
ctx = CryptContext(schemes=["bcrypt", "argon2", "pbkdf2_sha256"], deprecated="auto")

# =============================================================================
# hashlib.scrypt (stdlib)
# =============================================================================
dk = hashlib.scrypt(b"password", salt=b"salt", n=2**14, r=8, p=1)

# =============================================================================
# Django password hashing
# =============================================================================
from django.contrib.auth.hashers import make_password, check_password

hashed = make_password("password")
valid = check_password("password", hashed)

# =============================================================================
# Werkzeug password hashing
# =============================================================================
from werkzeug.security import generate_password_hash, check_password_hash

hashed_wz = generate_password_hash("password")
valid_wz = check_password_hash(hashed_wz, "password")

# =============================================================================
# argon2-cffi — check_needs_rehash
# =============================================================================
needs_rehash = ph.check_needs_rehash(a2_hash)

# =============================================================================
# scrypt — encrypt / decrypt
# =============================================================================
import scrypt

scrypt_encrypted = scrypt.encrypt(b"input data", b"password", maxtime=0.5)
scrypt_decrypted = scrypt.decrypt(scrypt_encrypted, b"password", maxtime=0.5)
