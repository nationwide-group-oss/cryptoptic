"""
Test suite for JwCrypto.ql — jwcrypto library usage (JWK, JWKS, JWT, JWS, JWE).
Each call site below should be detected by the query.
"""

from jwcrypto import jwk, jws, jwe, jwt
from jwcrypto.jwk import JWK, JWKSet
from jwcrypto.jws import JWS
from jwcrypto.jwe import JWE
from jwcrypto.jwt import JWT

# =============================================================================
# JWK key generation
# =============================================================================

# RSA key
rsa_key = JWK.generate(kty="RSA", size=2048)

# EC keys with various curves
ec_key_p256 = JWK.generate(kty="EC", crv="P-256")
ec_key_p384 = JWK.generate(kty="EC", crv="P-384")
ec_key_p521 = JWK.generate(kty="EC", crv="P-521")

# OKP keys (EdDSA / X25519)
okp_key_ed25519 = JWK.generate(kty="OKP", crv="Ed25519")
okp_key_ed448 = JWK.generate(kty="OKP", crv="Ed448")
okp_key_x25519 = JWK.generate(kty="OKP", crv="X25519")

# Symmetric key
oct_key = JWK.generate(kty="oct", size=256)

# Nested attribute access: jwk.JWK.generate(...)
rsa_key_nested = jwk.JWK.generate(kty="RSA", size=4096)

# =============================================================================
# JWK import
# =============================================================================

# JWK.from_json — import from serialised JSON string
imported_key = JWK.from_json('{"kty":"RSA","n":"...","e":"AQAB"}')

# JWK constructor — import from dict / PEM / raw bytes
jwk_from_dict = JWK(**{"kty": "RSA", "n": "...", "e": "AQAB"})

# Nested: jwk.JWK.from_json(...)
imported_nested = jwk.JWK.from_json('{"kty":"EC","crv":"P-256"}')

# =============================================================================
# JWKS key set
# =============================================================================

# JWKSet constructor
key_set = JWKSet()

# JWKSet.from_json
loaded_set = JWKSet.from_json('{"keys":[]}')

# Nested: jwk.JWKSet.from_json(...)
loaded_nested = jwk.JWKSet.from_json('{"keys":[]}')

# =============================================================================
# JWT — signing and encryption
# =============================================================================

# JWT constructor
jwt_obj = JWT(header={"alg": "RS256"}, claims={"sub": "user123"})

# JWT.make_signed_token — produces compact serialisation
jwt_obj.make_signed_token(rsa_key)

# JWT.make_encrypted_token — produces encrypted JWT
jwt_obj_enc = JWT(
    header={"alg": "RSA-OAEP", "enc": "A256GCM"}, claims={"sub": "user123"}
)
jwt_obj_enc.make_encrypted_token(rsa_key)

# JWT.validate
jwt_obj.validate(rsa_key)

# =============================================================================
# JWS — signing
# =============================================================================

# JWS constructor
jws_obj = JWS(b"payload data")

# JWS.add_signature with alg keyword
jws_obj.add_signature(rsa_key, alg="RS256")
jws_obj.add_signature(ec_key_p256, alg="ES256")

# JWS verification
jws_obj.verify_compact(rsa_key)
jws_obj.deserialize_compact("token_string")
jws_obj.deserialize("full_jws_json")

# =============================================================================
# JWE — encryption
# =============================================================================

# JWE constructor
jwe_obj = JWE(b"plaintext", protected='{"alg":"RSA-OAEP","enc":"A256GCM"}')

# JWE.decrypt
jwe_obj.decrypt(rsa_key)

# =============================================================================
# JWK instance methods
# =============================================================================

# thumbprint
tp = rsa_key.thumbprint()

# export methods
exported = rsa_key.export()
exported_pub = rsa_key.export_public()
exported_priv = rsa_key.export_private()
exported_pem = rsa_key.export_to_pem()

# =============================================================================
# JWK — from_password, from_pem, import_from_pem, get_op_key, thumbprint_uri
# =============================================================================

# JWK.from_password
password_key = JWK.from_password("my-secret-password")

# JWK.from_pem
with open("public.pem", "rb") as f:
    pem_key = JWK.from_pem(f.read())

# JWK.import_from_pem (instance method)
new_key = JWK()
new_key.import_from_pem(b"-----BEGIN PUBLIC KEY-----...")

# JWK.get_op_key
op_key = rsa_key.get_op_key("verify")

# JWK.thumbprint_uri
tp_uri = rsa_key.thumbprint_uri()

# Nested: jwk.JWK.from_password / jwk.JWK.from_pem
password_key_nested = jwk.JWK.from_password("another-password")
pem_key_nested = jwk.JWK.from_pem(b"-----BEGIN PUBLIC KEY-----...")

# =============================================================================
# JWKSet instance methods — get_key, get_keys, import_keyset
# =============================================================================
fetched_key = key_set.get_key("my-key-id")
fetched_keys = key_set.get_keys("my-key-id")
key_set.import_keyset('{"keys":[]}')

# =============================================================================
# JWS — from_jose_token, verify, serialize
# =============================================================================

# JWS.from_jose_token
jws_from_token = JWS.from_jose_token("eyJhbGciOiJSUzI1NiJ9...")
jws_nested_from_token = jws.JWS.from_jose_token("eyJhbGciOiJSUzI1NiJ9...")

# JWS.verify
jws_obj.verify(rsa_key)

# JWS.serialize
jws_serialized = jws_obj.serialize()
jws_compact = jws_obj.serialize(compact=True)

# =============================================================================
# JWE — from_jose_token, add_recipient, serialize
# =============================================================================

# JWE.from_jose_token
jwe_from_token = JWE.from_jose_token("eyJhbGciOiJSU0EtT0FFUCJ9...")
jwe_nested_from_token = jwe.JWE.from_jose_token("eyJhbGciOiJSU0EtT0FFUCJ9...")

# JWE.add_recipient
jwe_obj.add_recipient(rsa_key)

# JWE.serialize
jwe_serialized = jwe_obj.serialize()
jwe_compact = jwe_obj.serialize(compact=True)

# =============================================================================
# JWT — from_jose_token, deserialize, serialize
# =============================================================================

# JWT.from_jose_token
jwt_from_token = JWT.from_jose_token("eyJhbGciOiJSUzI1NiJ9...")
jwt_nested_from_token = jwt.JWT.from_jose_token("eyJhbGciOiJSUzI1NiJ9...")

# JWT.deserialize
jwt_deser = JWT()
jwt_deser.deserialize("eyJhbGciOiJSUzI1NiJ9...", key=rsa_key)

# JWT.serialize
jwt_token_str = jwt_obj.serialize()

# =============================================================================
# JWS.deserialize — deserialize a JWS token (optionally verify)
# =============================================================================
jws_deser = JWS()
jws_deser.deserialize('{"payload":"...","signatures":[...]}', key=rsa_key)

# =============================================================================
# JWE.deserialize — deserialize a JWE token (optionally decrypt)
# =============================================================================
jwe_deser = JWE()
jwe_deser.deserialize(
    "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0...", key=sym_key
)
