/**
 * @name Crypto inventory — jwcrypto (Python)
 * @description Inventory of jwcrypto library usage including JWK/JWKS key
 *              management, JWT signing and verification, JWS, and JWE
 *              encryption operations.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/python-cbom-jwcrypto
 * @tags security
 */

import python
import lib.PyCryptoCommon

/**
 * Holds if `call` invokes `outer.inner.method(...)` where `outer` is a simple
 * Name. Handles two-level attribute access such as `jwk.JWK.generate(...)`.
 */
predicate isNestedAttrCall(Call call, string outerName, string innerName, string methodName) {
  exists(Attribute outerAttr, Attribute innerAttr, Name base |
    call.getFunc() = outerAttr and
    outerAttr.getName() = methodName and
    outerAttr.getObject() = innerAttr and
    innerAttr.getName() = innerName and
    innerAttr.getObject() = base and
    base.getId() = outerName
  )
}

from Call call, string algo, string api
where
  api = "jwcrypto" and
  (
    // ==========================================================================
    // JWK key generation
    // Handles: jwk.JWK.generate(kty='RSA', size=2048)
    //          JWK.generate(kty='EC', crv='P-256')   [from jwcrypto.jwk import JWK]
    // ==========================================================================
    (
      (
        isAttrCall(call, "JWK", "generate") or
        isNestedAttrCall(call, "jwk", "JWK", "generate")
      ) and
      (
        (getKeywordString(call, "kty") = "RSA" and algo = "rsa-keygen")
        or
        (
          getKeywordString(call, "kty") = "EC" and
          (
            exists(string crv | crv = resolveKeywordArg(call, "crv") |
              algo = "ec-keygen-" + crv
            )
            or
            (not exists(resolveKeywordArg(call, "crv")) and algo = "unresolved")
          )
        )
        or
        (
          getKeywordString(call, "kty") = "OKP" and
          (
            exists(string crv | crv = resolveKeywordArg(call, "crv") |
              algo = "okp-keygen-" + crv
            )
            or
            (not exists(resolveKeywordArg(call, "crv")) and algo = "unresolved")
          )
        )
        or
        (getKeywordString(call, "kty") = "oct" and algo = "symmetric-keygen")
        or
        (not exists(getKeywordString(call, "kty")) and algo = "unresolved")
      )
    )

    or

    // JWK import from serialised JSON string
    (
      (
        isAttrCall(call, "JWK", "from_json") or
        isNestedAttrCall(call, "jwk", "JWK", "from_json")
      ) and
      algo = "jwk-import-json"
    )

    or

    // JWK.from_password(password) — create symmetric key from password
    (
      (
        isAttrCall(call, "JWK", "from_password") or
        isNestedAttrCall(call, "jwk", "JWK", "from_password")
      ) and
      algo = "jwk-from-password"
    )

    or

    // JWK.from_pem(data, password) — import key from PEM
    (
      (
        isAttrCall(call, "JWK", "from_pem") or
        isNestedAttrCall(call, "jwk", "JWK", "from_pem")
      ) and
      algo = "jwk-from-pem"
    )

    or

    // JWK constructor — import from dict / PEM / raw bytes
    (
      isConstructorCall(call, "JWK") and
      algo = "jwk-import"
    )

    or

    // ==========================================================================
    // JWKS key set
    // Handles: JWKSet() / jwk.JWKSet() / JWKSet.from_json(...)
    // ==========================================================================
    (
      (
        isConstructorCall(call, "JWKSet") or
        isAttrCall(call, "JWKSet", "from_json") or
        isNestedAttrCall(call, "jwk", "JWKSet", "from_json")
      ) and
      algo = "jwkset"
    )

    or

    // JWKSet instance methods: get_key, get_keys, import_keyset
    // Note: JWKSet.export() is caught by the JWK instance methods catch-all as jwk-export
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "get_key" and algo = "jwkset-get-key") or
          (attr.getName() = "get_keys" and algo = "jwkset-get-keys") or
          (attr.getName() = "import_keyset" and algo = "jwkset-import")
        )
      ) and
      (
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          n.getId() = "JWKSet"
        ) or
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          a.getObject().(Name).getId() = "jwk"
        )
      )
    )

    or

    // ==========================================================================
    // JWT — jwt.JWT(header={'alg': 'RS256'}, claims={...})
    //         JWT(header=..., ...)   [from jwcrypto.jwt import JWT]
    // Note: algorithm lives inside the header dict literal; indexed Dict access
    // (getKey(int)/getValue(int)) is unavailable in all codeql/python-all
    // versions, so alg is not extracted here.
    // ==========================================================================
    (
      (
        isConstructorCall(call, "JWT") or
        isAttrCall(call, "jwt", "JWT")
      ) and
      algo = "jwt"
    )

    or

    // JWT.make_signed_token(key) — produces the compact serialisation
    (
      exists(Attribute attr | call.getFunc() = attr and attr.getName() = "make_signed_token") and
      algo = "jwt-sign"
    )

    or

    // ==========================================================================
    // JWS — jws.JWS(payload) / JWS(payload)  [from jwcrypto.jws import JWS]
    // ==========================================================================
    (
      (
        isConstructorCall(call, "JWS") or
        isAttrCall(call, "jws", "JWS")
      ) and
      algo = "jws"
    )

    or

    // JWS.add_signature(key, alg='RS256') — direct alg keyword arg is extractable;
    // alg inside a protected={...} dict is not (Dict indexed API unavailable).
    (
      exists(Attribute attr | call.getFunc() = attr and attr.getName() = "add_signature") and
      (
        exists(string alg | alg = resolveKeywordArg(call, "alg") |
          algo = "jws-sign-" + alg
        )
        or
        (not exists(resolveKeywordArg(call, "alg")) and algo = "unresolved")
      )
    )

    or

    // JWS.from_jose_token(token) — create JWS from serialized token
    (
      (
        isAttrCall(call, "JWS", "from_jose_token") or
        isNestedAttrCall(call, "jws", "JWS", "from_jose_token")
      ) and
      algo = "jws-from-token"
    )

    or

    // JWS.verify(key) — verify a JWS signature
    // JWS.serialize(compact) — serialize JWS to string
    // JWS.deserialize(raw_jws, key, alg) — deserialize and optionally verify
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "verify" and algo = "jws-verify") or
          (attr.getName() = "serialize" and algo = "jws-serialize") or
          (attr.getName() = "deserialize" and algo = "jws-deserialize")
        ) and
        (
          attr.getObject().toString().matches("%[Jj][Ww][Ss]%") or
          attr.getObject().toString().matches("%jws%") or
          attr.getObject().toString().matches("%sig%") or
          attr.getObject().toString().matches("%token%")
        )
      ) and
      (
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          n.getId() = "JWS"
        ) or
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          a.getObject().(Name).getId() = "jws"
        )
      )
    )

    or

    // ==========================================================================
    // JWE — jwe.JWE(plaintext, protected=...) / JWE(...)
    // Note: alg/enc live inside the protected dict literal; indexed Dict access
    // is unavailable, so algorithm values are not extracted.
    // ==========================================================================
    (
      (
        isConstructorCall(call, "JWE") or
        isAttrCall(call, "jwe", "JWE")
      ) and
      algo = "jwe"
    )

    or

    // JWE.from_jose_token(token) — create JWE from serialized token
    (
      (
        isAttrCall(call, "JWE", "from_jose_token") or
        isNestedAttrCall(call, "jwe", "JWE", "from_jose_token")
      ) and
      algo = "jwe-from-token"
    )

    or

    // JWE.add_recipient(key, header) — encrypt for a recipient
    (
      exists(Attribute attr | call.getFunc() = attr and attr.getName() = "add_recipient") and
      algo = "jwe-add-recipient" and
      (
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "JWE" or n.getId() = "JWK")
        ) or
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          a.getObject().(Name).getId() = "jwe"
        )
      )
    )

    or

    // JWE.serialize(compact) — serialize JWE to string
    // JWE.deserialize(raw_jwe, key) — deserialize and optionally decrypt
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "serialize" and algo = "jwe-serialize") or
          (attr.getName() = "deserialize" and algo = "jwe-deserialize")
        ) and
        (
          attr.getObject().toString().matches("%[Jj][Ww][Ee]%") or
          attr.getObject().toString().matches("%jwe%") or
          attr.getObject().toString().matches("%enc%") or
          attr.getObject().toString().matches("%cipher%")
        )
      ) and
      (
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          n.getId() = "JWE"
        ) or
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          a.getObject().(Name).getId() = "jwe"
        )
      )
    )

    or

    // ==========================================================================
    // JWT.make_encrypted_token(key) — produces encrypted JWT
    // ==========================================================================
    (
      exists(Attribute attr | call.getFunc() = attr and attr.getName() = "make_encrypted_token") and
      algo = "jwt-encrypt"
    )

    or

    // ==========================================================================
    // JWT — from_jose_token, deserialize, serialize
    // ==========================================================================
    (
      (
        isAttrCall(call, "JWT", "from_jose_token") or
        isNestedAttrCall(call, "jwt", "JWT", "from_jose_token")
      ) and
      algo = "jwt-from-token"
    )

    or

    // JWT.deserialize(jwt, key) — deserialize a JWT token
    // JWT.serialize(compact) — serialize JWT to string
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "deserialize" and algo = "jwt-deserialize") or
          (attr.getName() = "serialize" and algo = "jwt-serialize")
        ) and
        (
          attr.getObject().toString().matches("%[Jj][Ww][Tt]%") or
          attr.getObject().toString().matches("%jwt%") or
          attr.getObject().toString().matches("%[Tt]oken%")
        )
      ) and
      (
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          n.getId() = "JWT"
        ) or
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          a.getObject().(Name).getId() = "jwt"
        )
      )
    )

    or

    // ==========================================================================
    // Verification / Deserialization methods (generic — guarded by file evidence)
    // These cover calls where the receiver name doesn't match specific heuristics
    // above, acting as a catch-all for jwcrypto files.
    // ==========================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "verify_compact" and algo = "jws-verify-compact") or
          (attr.getName() = "deserialize_compact" and algo = "jws-deserialize-compact") or
          (attr.getName() = "decrypt" and algo = "jwe-decrypt") or
          (attr.getName() = "validate" and algo = "jwt-validate")
        )
      ) and
      // Guard: only match in files using jwcrypto
      (
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "JWK" or n.getId() = "JWS" or n.getId() = "JWE" or
           n.getId() = "JWT" or n.getId() = "JWKSet")
        ) or
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          (a.getObject().(Name).getId() = "jwk" or a.getObject().(Name).getId() = "jws" or
           a.getObject().(Name).getId() = "jwe" or a.getObject().(Name).getId() = "jwt")
        )
      )
    )

    or

    // ==========================================================================
    // JWK instance methods — thumbprint, export, import_from_pem, get_op_key
    // ==========================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "thumbprint" and algo = "jwk-thumbprint") or
          (attr.getName() = "thumbprint_uri" and algo = "jwk-thumbprint-uri") or
          (attr.getName() = "export" and algo = "jwk-export") or
          (attr.getName() = "export_public" and algo = "jwk-export-public") or
          (attr.getName() = "export_private" and algo = "jwk-export-private") or
          (attr.getName() = "export_to_pem" and algo = "jwk-export-pem") or
          (attr.getName() = "import_from_pem" and algo = "jwk-import-pem") or
          (attr.getName() = "get_op_key" and algo = "jwk-get-op-key")
        )
      ) and
      (
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "JWK" or n.getId() = "JWKSet")
        ) or
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          a.getObject().(Name).getId() = "jwk"
        )
      )
    )
  )
select call, "algo=" + algo + ", api=" + api
