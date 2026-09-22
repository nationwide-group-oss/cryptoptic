/**
 * @name Crypto inventory — Authlib (Python)
 * @description Inventory of Authlib library usage covering JOSE (JWT, JWS, JWE)
 *              and JsonWebKey operations for both the v0.x and v1.x APIs.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/python-cbom-authlib
 * @tags security
 */

import python
import lib.PyCryptoCommon

from Call call, string algo, string api
where
  api = "Authlib" and
  (
    // ==========================================================================
    // JWT — authlib.jose.jwt
    // Authlib calling convention: jwt.encode({'alg': 'RS256'}, payload, key)
    // Distinguishable from PyJWT because the header dict is positional arg 0,
    // not a keyword argument named 'algorithm'.
    // ==========================================================================

    // jwt.encode({'alg': 'RS256'}, payload, key)
    // Authlib convention: first positional arg is the header dict (not the payload).
    // Distinguished from PyJWT (which uses algorithm= keyword) by checking the
    // first arg is a Dict and no algorithm= keyword is present.
    // Note: alg is inside the dict; indexed Dict access unavailable, not extracted.
    (
      isAttrCall(call, "jwt", "encode") and
      not exists(getKeywordString(call, "algorithm")) and
      call.getPositionalArg(0) instanceof Dict and
      algo = "jwt-encode"
    )

    or

    // jwt.decode(token, key)
    // Guarded: only match when the file contains Authlib-specific constructs
    // to avoid false positives on PyJWT / python-jose jwt.decode() calls.
    (
      isAttrCall(call, "jwt", "decode") and
      fileUsesAuthlib(call.getLocation().getFile()) and
      algo = "jwt-decode"
    )

    or

    // ==========================================================================
    // JWS — authlib.jose.jws  /  JsonWebSignature
    // Authlib-specific method names: serialize_compact / deserialize_compact
    // ==========================================================================

    // jws.serialize_compact({'alg': 'RS256'}, payload, key)
    // Method name is Authlib-specific; alg is inside the header dict (not extracted).
    (
      exists(Attribute attr | call.getFunc() = attr and attr.getName() = "serialize_compact") and
      not exists(Attribute outer |
        call.getFunc() = outer and outer.getObject().(Name).getId() = "jwe"
      ) and
      algo = "jws-sign"
    )

    or

    // jws.deserialize_compact(token, key)
    (
      exists(Attribute attr | call.getFunc() = attr and attr.getName() = "deserialize_compact") and
      algo = "jws-verify"
    )

    or

    // JsonWebSignature() constructor (Authlib v0.x / v1.x)
    (
      isConstructorCall(call, "JsonWebSignature") and
      algo = "jws"
    )

    or

    // ==========================================================================
    // JWE — authlib.jose.jwe  /  JsonWebEncryption
    // ==========================================================================

    // jwe.serialize_compact({'alg': 'RSA-OAEP', 'enc': 'A256GCM'}, payload, key)
    // Identified by the jwe module object on the call receiver.
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "serialize_compact" and
        attr.getObject().(Name).getId() = "jwe"
      ) and
      algo = "jwe-encrypt"
    )

    or

    // jwe.deserialize_compact(token, key)
    (
      exists(Attribute attr | call.getFunc() = attr and attr.getName() = "deserialize_compact") and
      exists(Attribute outer | call.getFunc() = outer and outer.getObject().(Name).getId() = "jwe") and
      algo = "jwe-decrypt"
    )

    or

    // JsonWebEncryption() constructor (Authlib v0.x / v1.x)
    (
      isConstructorCall(call, "JsonWebEncryption") and
      algo = "jwe"
    )

    or

    // ==========================================================================
    // JsonWebKey — authlib.jose.JsonWebKey
    // v0.x: JsonWebKey.import_key({...})  /  JsonWebKey.generate_key('RSA', 2048)
    // v1.x: JsonWebKey.import_key(...)    /  JsonWebKey.generate_key('EC', 'P-256')
    // ==========================================================================

    // JsonWebKey.import_key(key_data)
    (
      isAttrCall(call, "JsonWebKey", "import_key") and
      algo = "jwk-import"
    )

    or

    // JsonWebKey.generate_key(kty, crv_or_bits, ...)
    (
      isAttrCall(call, "JsonWebKey", "generate_key") and
      (
        // RSA key: generate_key('RSA', 2048)
        (resolvePositionalArg(call, 0) = "rsa" and algo = "rsa-keygen")
        or
        // EC key: generate_key('EC', 'P-256')
        (
          resolvePositionalArg(call, 0) = "ec" and
          (
            exists(string crv | crv = resolvePositionalArg(call, 1) |
              algo = "ec-keygen-" + crv
            )
            or
            (not exists(resolvePositionalArg(call, 1)) and algo = "unresolved")
          )
        )
        or
        // OKP key: generate_key('OKP', 'Ed25519')
        (
          resolvePositionalArg(call, 0) = "okp" and
          (
            exists(string crv | crv = resolvePositionalArg(call, 1) |
              algo = "okp-keygen-" + crv
            )
            or
            (not exists(resolvePositionalArg(call, 1)) and algo = "unresolved")
          )
        )
        or
        // Symmetric: generate_key('oct', 256)
        (resolvePositionalArg(call, 0) = "oct" and algo = "symmetric-keygen")
        or
        // Unresolvable kty
        (not exists(resolvePositionalArg(call, 0)) and algo = "unresolved")
      )
    )

    or

    // ==========================================================================
    // Authlib v1.x key-type-specific classes
    // RSAKey.generate_key(2048) / ECKey.generate_key('P-256')
    // OKPKey.generate_key('Ed25519') / OctKey.generate_key(256)
    // ==========================================================================

    (isAttrCall(call, "RSAKey", "generate_key") and algo = "rsa-keygen")
    or
    (isAttrCall(call, "RSAKey", "import_key") and algo = "rsa-import")
    or
    (
      isAttrCall(call, "ECKey", "generate_key") and
      (
        exists(string crv | crv = resolvePositionalArg(call, 0) |
          algo = "ec-keygen-" + crv
        )
        or
        (not exists(resolvePositionalArg(call, 0)) and algo = "unresolved")
      )
    )
    or
    (isAttrCall(call, "ECKey", "import_key") and algo = "ec-import")
    or
    (
      isAttrCall(call, "OKPKey", "generate_key") and
      (
        exists(string crv | crv = resolvePositionalArg(call, 0) |
          algo = "okp-keygen-" + crv
        )
        or
        (not exists(resolvePositionalArg(call, 0)) and algo = "unresolved")
      )
    )
    or
    (isAttrCall(call, "OKPKey", "import_key") and algo = "okp-import")
    or
    (isAttrCall(call, "OctKey", "generate_key") and algo = "symmetric-keygen")
    or
    (isAttrCall(call, "OctKey", "import_key") and algo = "symmetric-import")

    or

    // ==========================================================================
    // JsonWebKey.import_key_set(keys) — JWKS import
    // ==========================================================================
    (isAttrCall(call, "JsonWebKey", "import_key_set") and algo = "jwks-import")

    or

    // ==========================================================================
    // JWS/JWE JSON serialization — serialize_json / deserialize_json
    // ==========================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "serialize_json"
      ) and
      fileUsesAuthlib(call.getLocation().getFile()) and
      algo = "jose-serialize-json"
    )

    or

    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "deserialize_json"
      ) and
      fileUsesAuthlib(call.getLocation().getFile()) and
      algo = "jose-deserialize-json"
    )

    or

    // ==========================================================================
    // JWS/JWE generic serialize / deserialize (auto-dispatch to compact or JSON)
    // jws.serialize(header, payload, key)  /  jws.deserialize(s, key)
    // jwe.serialize(header, payload, key)  /  jwe.deserialize(obj, key)
    // ==========================================================================
    (
      isAttrCall(call, "jws", "serialize") and
      fileUsesAuthlib(call.getLocation().getFile()) and
      algo = "jws-sign"
    )

    or

    (
      isAttrCall(call, "jws", "deserialize") and
      fileUsesAuthlib(call.getLocation().getFile()) and
      algo = "jws-verify"
    )

    or

    (
      isAttrCall(call, "jwe", "serialize") and
      fileUsesAuthlib(call.getLocation().getFile()) and
      algo = "jwe-encrypt"
    )

    or

    (
      isAttrCall(call, "jwe", "deserialize") and
      fileUsesAuthlib(call.getLocation().getFile()) and
      algo = "jwe-decrypt"
    )

    or

    // ==========================================================================
    // JsonWebToken constructor — jwt = JsonWebToken(['RS256'])
    // Creates a JWT instance with limited algorithms
    // ==========================================================================
    (
      isConstructorCall(call, "JsonWebToken") and
      algo = "jwt"
    )

    or

    // ==========================================================================
    // Key instance methods (on objects returned by import_key / generate_key)
    // key.thumbprint() — RFC7638 JWK Thumbprint (uses hashing)
    // key.as_json(is_private) — export key material to JSON
    // ==========================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "thumbprint"
      ) and
      fileUsesAuthlib(call.getLocation().getFile()) and
      algo = "jwk-thumbprint"
    )

    or

    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "as_json"
      ) and
      fileUsesAuthlib(call.getLocation().getFile()) and
      algo = "jwk-export"
    )
  )
select call, "algo=" + algo + ", api=" + api
