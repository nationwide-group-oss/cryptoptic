"""
Test suite for Cryptography.ql — pyca/cryptography library usage.
Each call site below should be detected by the query.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    AESCCM,
    ChaCha20Poly1305,
    AESGCMSIV,
    AESSIV,
    AESOCB3,
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash, ConcatKDFHMAC
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, KBKDFCMAC
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh, padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.fernet import Fernet, MultiFernet
from cryptography import x509

# =============================================================================
# Hash Algorithms
# =============================================================================
h_sha1 = hashes.SHA1()
h_sha224 = hashes.SHA224()
h_sha256 = hashes.SHA256()
h_sha384 = hashes.SHA384()
h_sha512 = hashes.SHA512()
h_sha3_256 = hashes.SHA3_256()
h_sha3_384 = hashes.SHA3_384()
h_sha3_512 = hashes.SHA3_512()
h_md5 = hashes.MD5()
h_blake2b = hashes.BLAKE2b(64)
h_blake2s = hashes.BLAKE2s(32)
h_sm3 = hashes.SM3()
h_shake128 = hashes.SHAKE128(32)
h_shake256 = hashes.SHAKE256(64)
h_sha512_224 = hashes.SHA512_224()
h_sha512_256 = hashes.SHA512_256()
h_sha3_224 = hashes.SHA3_224()

# Hash object
digest = hashes.Hash(hashes.SHA256())

# =============================================================================
# AEAD Ciphers
# =============================================================================
aesgcm = AESGCM(b"\x00" * 32)
aesccm = AESCCM(b"\x00" * 32)
cc20 = ChaCha20Poly1305(b"\x00" * 32)
aesgcmsiv = AESGCMSIV(b"\x00" * 32)
aessiv = AESSIV(b"\x00" * 64)
aesocb3 = AESOCB3(b"\x00" * 32)

# =============================================================================
# Cipher with algorithm + mode
# =============================================================================
cipher_aes_cbc = Cipher(algorithms.AES(b"\x00" * 32), modes.CBC(b"\x00" * 16))
cipher_aes_gcm = Cipher(algorithms.AES(b"\x00" * 32), modes.GCM(b"\x00" * 12))
cipher_aes_ctr = Cipher(algorithms.AES(b"\x00" * 32), modes.CTR(b"\x00" * 16))
cipher_aes_ecb = Cipher(algorithms.AES(b"\x00" * 32), modes.ECB())
cipher_aes_cfb = Cipher(algorithms.AES(b"\x00" * 32), modes.CFB(b"\x00" * 16))
cipher_aes_ofb = Cipher(algorithms.AES(b"\x00" * 32), modes.OFB(b"\x00" * 16))
cipher_3des = Cipher(algorithms.TripleDES(b"\x00" * 24), modes.CBC(b"\x00" * 8))
cipher_camellia = Cipher(algorithms.Camellia(b"\x00" * 32), modes.CBC(b"\x00" * 16))
cipher_chacha20 = Cipher(algorithms.ChaCha20(b"\x00" * 32, b"\x00" * 16), None)
cipher_aes_cfb8 = Cipher(algorithms.AES(b"\x00" * 32), modes.CFB8(b"\x00" * 16))
cipher_aes_xts = Cipher(algorithms.AES(b"\x00" * 64), modes.XTS(b"\x00" * 16))
cipher_cast5 = Cipher(algorithms.CAST5(b"\x00" * 16), modes.CBC(b"\x00" * 8))
cipher_sm4 = Cipher(algorithms.SM4(b"\x00" * 16), modes.CBC(b"\x00" * 16))
cipher_blowfish = Cipher(algorithms.Blowfish(b"\x00" * 16), modes.CBC(b"\x00" * 8))
cipher_arc4 = Cipher(algorithms.ARC4(b"\x00" * 16), None)
cipher_seed = Cipher(algorithms.SEED(b"\x00" * 16), modes.CBC(b"\x00" * 16))
cipher_idea = Cipher(algorithms.IDEA(b"\x00" * 16), modes.CBC(b"\x00" * 8))

# Encryptor/Decryptor
encryptor = cipher_aes_cbc.encryptor()
decryptor = cipher_aes_cbc.decryptor()

# =============================================================================
# KDFs
# =============================================================================
kdf_pbkdf2 = PBKDF2HMAC(
    algorithm=hashes.SHA256(), length=32, salt=b"salt", iterations=480000
)
kdf_pbkdf2_sha1 = PBKDF2HMAC(
    algorithm=hashes.SHA1(), length=32, salt=b"salt", iterations=480000
)
kdf_scrypt = Scrypt(salt=b"salt", length=32, n=2**14, r=8, p=1)
kdf_hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"salt", info=b"info")
kdf_hkdf_expand = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"info")
kdf_x963 = X963KDF(algorithm=hashes.SHA256(), length=32, sharedinfo=b"info")
kdf_concat_hash = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=b"info")
kdf_concat_hmac = ConcatKDFHMAC(
    algorithm=hashes.SHA256(), length=32, salt=b"salt", otherinfo=b"info"
)
kdf_kbkdf_hmac = KBKDFHMAC(
    algorithm=hashes.SHA256(),
    mode=None,
    length=32,
    rlen=4,
    llen=4,
    location=None,
    label=b"label",
    context=b"context",
    fixed=None,
)
kdf_kbkdf_cmac = KBKDFCMAC(
    algorithm=algorithms.AES,
    mode=None,
    length=32,
    rlen=4,
    llen=4,
    location=None,
    label=b"label",
    context=b"context",
    fixed=None,
)

# =============================================================================
# Asymmetric — RSA
# =============================================================================
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# RSA Padding
oaep_padding = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
pss_padding = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)
pkcs1_padding = padding.PKCS1v15()

# =============================================================================
# Asymmetric — EC
# =============================================================================
ec_key_p256 = ec.generate_private_key(ec.SECP256R1())
ec_key_p384 = ec.generate_private_key(ec.SECP384R1())
ec_key_p521 = ec.generate_private_key(ec.SECP521R1())
ec_key_k256 = ec.generate_private_key(ec.SECP256K1())
ec_key_bp256 = ec.generate_private_key(ec.BrainpoolP256R1())
ec_key_bp384 = ec.generate_private_key(ec.BrainpoolP384R1())
ec_key_bp512 = ec.generate_private_key(ec.BrainpoolP512R1())
ec_key_p192 = ec.generate_private_key(ec.SECP192R1())
ec_key_p224 = ec.generate_private_key(ec.SECP224R1())
ec_derived = ec.derive_private_key(0xDEADBEEF, ec.SECP256R1())

# =============================================================================
# Asymmetric — Modern curves
# =============================================================================
ed25519_key = Ed25519PrivateKey.generate()
ed448_key = Ed448PrivateKey.generate()
x25519_key = X25519PrivateKey.generate()
x448_key = X448PrivateKey.generate()

# =============================================================================
# Asymmetric — DSA & DH
# =============================================================================
dsa_key = dsa.generate_private_key(key_size=2048)
dsa_params = dsa.generate_parameters(key_size=2048)
dh_params = dh.generate_parameters(generator=2, key_size=2048)

# =============================================================================
# HMAC via cryptography
# =============================================================================
h_hmac = HMAC(b"key", hashes.SHA256())

# =============================================================================
# CMAC
# =============================================================================
c_cmac = CMAC(algorithms.AES(b"\x00" * 32))

# =============================================================================
# Poly1305
# =============================================================================
p1305 = Poly1305(b"\x00" * 32)

# =============================================================================
# X.509 Certificates
# =============================================================================
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseBuilder
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7

cert = x509.load_pem_x509_certificate(pem_data)
cert_der = x509.load_der_x509_certificate(der_data)
csr = x509.load_pem_x509_csr(csr_pem)
crl = x509.load_pem_x509_crl(crl_pem)
builder = x509.CertificateBuilder()
crl_builder = x509.CertificateRevocationListBuilder()
ocsp_req = OCSPRequestBuilder()
ocsp_resp = OCSPResponseBuilder()
csr_builder = x509.CertificateSigningRequestBuilder()
revoked_builder = x509.RevokedCertificateBuilder()
serial = x509.random_serial_number()
pkcs12_data = pkcs12.load_key_and_certificates(p12_data, b"password")
pkcs12_serialized = pkcs12.serialize_key_and_certificates(
    b"name", key, cert, None, serialization.BestAvailableEncryption(b"pw")
)
pkcs7_builder = pkcs7.PKCS7SignatureBuilder()
pkcs7_certs = pkcs7.serialize_certificates(certs, serialization.Encoding.PEM)

# =============================================================================
# Key Serialization
# =============================================================================
priv_loaded = serialization.load_pem_private_key(pem_data, password=None)
pub_loaded = serialization.load_pem_public_key(pem_data)
priv_der = serialization.load_der_private_key(der_data, password=None)
pub_der = serialization.load_der_public_key(der_data)
ssh_pub = serialization.load_ssh_public_key(ssh_data)
ssh_priv = serialization.load_ssh_private_key(ssh_priv_data, password=None)
pem_params = serialization.load_pem_parameters(pem_params_data)
no_enc = serialization.NoEncryption()

# =============================================================================
# Fernet
# =============================================================================
fernet_key = Fernet.generate_key()
f = Fernet(fernet_key)
mf = MultiFernet([f, Fernet(Fernet.generate_key())])
fernet_encrypted = f.encrypt(b"secret data")
fernet_decrypted = f.decrypt(fernet_encrypted)

# =============================================================================
# OCSP load operations
# =============================================================================
from cryptography.x509 import ocsp

ocsp_req_loaded = ocsp.load_der_ocsp_request(ocsp_der_data)
ocsp_resp_loaded = ocsp.load_der_ocsp_response(ocsp_resp_der_data)

# =============================================================================
# Prehashed utility
# =============================================================================
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

prehashed = Prehashed(hashes.SHA256())

# =============================================================================
# AEAD generate_key() class methods
# =============================================================================
aesgcm_key = AESGCM.generate_key(bit_length=256)
aesccm_key = AESCCM.generate_key(bit_length=128)
cc20p1305_key = ChaCha20Poly1305.generate_key()
aesgcmsiv_key = AESGCMSIV.generate_key(bit_length=256)
aessiv_key = AESSIV.generate_key(bit_length=256)
aesocb3_key = AESOCB3.generate_key(bit_length=256)

# =============================================================================
# Ed25519/Ed448/X25519/X448 from_private_bytes
# =============================================================================
ed25519_priv_imported = Ed25519PrivateKey.from_private_bytes(b"\x00" * 32)
ed448_priv_imported = Ed448PrivateKey.from_private_bytes(b"\x00" * 57)
x25519_priv_imported = X25519PrivateKey.from_private_bytes(b"\x00" * 32)
x448_priv_imported = X448PrivateKey.from_private_bytes(b"\x00" * 56)

# =============================================================================
# ec.ECDSA — signature algorithm
# =============================================================================
ecdsa_algo = ec.ECDSA(hashes.SHA256())

# =============================================================================
# HOTP/TOTP — two-factor authentication
# =============================================================================
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.twofactor.totp import TOTP

hotp_instance = HOTP(b"\x00" * 20, 6, hashes.SHA1())
totp_instance = TOTP(b"\x00" * 20, 6, hashes.SHA1(), 30)

# =============================================================================
# RSA key construction from numbers
# =============================================================================
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicNumbers,
    RSAPrivateNumbers,
)

rsa_pub_nums = RSAPublicNumbers(65537, 123456789)
rsa_priv_nums = RSAPrivateNumbers(
    p=0, q=0, d=0, dmp1=0, dmq1=0, iqmp=0, public_numbers=rsa_pub_nums
)

# =============================================================================
# Key wrapping
# =============================================================================
from cryptography.hazmat.primitives.keywrap import (
    aes_key_wrap,
    aes_key_unwrap,
    aes_key_wrap_with_padding,
    aes_key_unwrap_with_padding,
)

wrapped = aes_key_wrap(b"\x00" * 16, b"\x00" * 16)
unwrapped = aes_key_unwrap(b"\x00" * 16, wrapped)
wrapped_pad = aes_key_wrap_with_padding(b"\x00" * 16, b"\x00" * 15)
unwrapped_pad = aes_key_unwrap_with_padding(b"\x00" * 16, wrapped_pad)

# =============================================================================
# x509.load_pem_x509_certificates (plural — PEM bundle)
# =============================================================================
certs_bundle = x509.load_pem_x509_certificates(pem_bundle_data)

# =============================================================================
# serialization.load_der_parameters
# =============================================================================
der_params = serialization.load_der_parameters(der_params_data)
