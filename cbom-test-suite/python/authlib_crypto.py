"""
Test suite for Authlib.ql — Authlib JOSE library usage (JWT, JWS, JWE, JWK).
Each call site below should be detected by the query.
"""

from authlib.jose import jwt, jws, jwe, JsonWebSignature, JsonWebEncryption, JsonWebKey
from authlib.jose import JsonWebToken, RSAKey, ECKey, OKPKey, OctKey

# =============================================================================
# JWT — authlib.jose.jwt
# =============================================================================

# jwt.encode — Authlib convention: header dict is first positional arg
token_rs256 = jwt.encode({"alg": "RS256"}, {"sub": "1234"}, "private_key")
token_es256 = jwt.encode({"alg": "ES256"}, {"sub": "1234"}, "private_key")
token_ps256 = jwt.encode({"alg": "PS256"}, {"sub": "1234"}, "private_key")

# jwt.decode
decoded = jwt.decode(token_rs256, "public_key")

# =============================================================================
# JWS — authlib.jose.jws / JsonWebSignature
# =============================================================================

# jws.serialize_compact — Authlib-specific method name
signed_compact = jws.serialize_compact({"alg": "RS256"}, b"payload", "private_key")

# jws.deserialize_compact
verified_payload = jws.deserialize_compact(signed_compact, "public_key")

# JsonWebSignature constructor (v0.x / v1.x)
jws_obj = JsonWebSignature()

# JWS JSON serialization
json_signed = jws.serialize_json({"alg": "RS256"}, b"payload", "private_key")
json_verified = jws.deserialize_json(json_signed, "public_key")

# =============================================================================
# JWE — authlib.jose.jwe / JsonWebEncryption
# =============================================================================

# jwe.serialize_compact
encrypted_compact = jwe.serialize_compact(
    {"alg": "RSA-OAEP", "enc": "A256GCM"}, b"plaintext", "public_key"
)

# jwe.deserialize_compact
decrypted = jwe.deserialize_compact(encrypted_compact, "private_key")

# JsonWebEncryption constructor
jwe_obj = JsonWebEncryption()

# =============================================================================
# JsonWebKey — key management
# =============================================================================

# JsonWebKey.import_key
imported_key = JsonWebKey.import_key({"kty": "RSA", "n": "...", "e": "AQAB"})

# JsonWebKey.import_key_set (JWKS)
key_set = JsonWebKey.import_key_set({"keys": [{"kty": "RSA", "n": "..."}]})

# JsonWebKey.generate_key — RSA
rsa_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)

# JsonWebKey.generate_key — EC
ec_key_p256 = JsonWebKey.generate_key("EC", "P-256", is_private=True)
ec_key_p384 = JsonWebKey.generate_key("EC", "P-384", is_private=True)

# JsonWebKey.generate_key — OKP (EdDSA)
okp_key_ed25519 = JsonWebKey.generate_key("OKP", "Ed25519", is_private=True)
okp_key_x25519 = JsonWebKey.generate_key("OKP", "X25519", is_private=True)

# JsonWebKey.generate_key — Symmetric (oct)
oct_key = JsonWebKey.generate_key("oct", 256, is_private=True)

# =============================================================================
# Authlib v1.x key-type-specific classes
# =============================================================================

# RSAKey
rsa_key2 = RSAKey.generate_key(2048)
rsa_imported = RSAKey.import_key("pem_data")

# ECKey
ec_key2 = ECKey.generate_key("P-256")
ec_imported = ECKey.import_key("pem_data")

# OKPKey
okp_key2 = OKPKey.generate_key("Ed25519")
okp_imported = OKPKey.import_key("pem_data")

# OctKey
oct_key2 = OctKey.generate_key(256)
oct_imported = OctKey.import_key("raw_bytes")

# =============================================================================
# JWS/JWE generic serialize/deserialize (auto-dispatch)
# =============================================================================

# jws.serialize — auto-dispatches to compact or JSON based on header format
signed_generic = jws.serialize({"alg": "RS256"}, b"payload", "private_key")

# jws.deserialize — auto-detects compact vs JSON format
verified_generic = jws.deserialize(signed_generic, "public_key")

# jwe.serialize — auto-dispatches to compact or JSON
encrypted_generic = jwe.serialize(
    {"alg": "RSA-OAEP", "enc": "A256GCM"}, b"plaintext", "public_key"
)

# jwe.deserialize — auto-detects format
decrypted_generic = jwe.deserialize(encrypted_generic, "private_key")

# =============================================================================
# JsonWebToken constructor — limited algorithms
# =============================================================================
limited_jwt = JsonWebToken(["RS256"])

# =============================================================================
# Key instance methods — thumbprint, as_json
# =============================================================================

# key.thumbprint() — RFC7638 JWK Thumbprint
key_thumb = rsa_key.thumbprint()

# key.as_json() — export key to JSON
key_json = rsa_key.as_json(is_private=False)
key_json_private = ec_key_p256.as_json(is_private=True)
