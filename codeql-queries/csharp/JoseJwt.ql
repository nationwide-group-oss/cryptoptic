/**
 * @name Crypto inventory — Jose.JWT (C#/.NET)
 * @description Inventory of jose-jwt (Jose.JWT NuGet) cryptographic API usage including
 *              JWT signing (JWS) and encryption (JWE) via JWT.Encode / JWT.Decode /
 *              JWT.Verify / JWT.Decrypt, JWE JSON serialization (JWE.Encrypt / JWE.Decrypt),
 *              and algorithm configuration via JwsAlgorithm / JweAlgorithm / JweEncryption.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/csharp-cbom-jose-jwt
 * @tags security
 */

import csharp

// Note: namespace guards are intentionally omitted — in --build-mode=none,
// NuGet types are unresolved so getNamespace().getFullName() returns "".
// Detection relies on class/enum names alone, which are sufficiently distinctive.

// ---------------------------------------------------------------------------
// JWT compact serialization operations (JWT static class)
// ---------------------------------------------------------------------------
predicate isJwtOperationDetection(Expr call, string algo) {
  // JWT.Encode / JWT.EncodeBytes — produce a signed (JWS) or encrypted (JWE) compact token
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = ["Encode", "EncodeBytes"] and
    mc.getTarget().getDeclaringType().getName() = "JWT" and
    algo = "jose-jwt-encode"
  )
  or
  // JWT.Decode / JWT.DecodeBytes / JWT.DecodeToObject — decode and verify or decrypt
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = ["Decode", "DecodeBytes", "DecodeToObject"] and
    mc.getTarget().getDeclaringType().getName() = "JWT" and
    algo = "jose-jwt-decode"
  )
  or
  // JWT.Verify / JWT.VerifyBytes (v5+) — dedicated signature verification
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = ["Verify", "VerifyBytes"] and
    mc.getTarget().getDeclaringType().getName() = "JWT" and
    algo = "jose-jwt-verify"
  )
  or
  // JWT.Decrypt / JWT.DecryptBytes (v5+) — dedicated JWE decryption
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = ["Decrypt", "DecryptBytes"] and
    mc.getTarget().getDeclaringType().getName() = "JWT" and
    algo = "jose-jwt-decrypt"
  )
  or
  // JWT.Payload / JWT.PayloadBytes / JWT.Headers — inspect without verification (insecure pattern)
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = ["Payload", "PayloadBytes", "Headers", "Signature", "SignatureBytes"] and
    mc.getTarget().getDeclaringType().getName() = "JWT" and
    algo = "jose-jwt-inspect"
  )
}

// ---------------------------------------------------------------------------
// JWE JSON serialization operations (JWE static class)
// ---------------------------------------------------------------------------
predicate isJweJsonOperationDetection(Expr call, string algo) {
  // JWE.Encrypt / JWE.EncryptBytes — produce a JSON-serialised JWE (multi-recipient)
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = ["Encrypt", "EncryptBytes"] and
    mc.getTarget().getDeclaringType().getName() = "JWE" and
    algo = "jose-jwe-encrypt"
  )
  or
  // JWE.Decrypt — decrypt a JSON-serialised JWE token
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = "Decrypt" and
    mc.getTarget().getDeclaringType().getName() = "JWE" and
    algo = "jose-jwe-decrypt"
  )
  or
  // JWE.Headers — parse JSON-serialised JWE without decryption (two-phase validation)
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = "Headers" and
    mc.getTarget().getDeclaringType().getName() = "JWE" and
    algo = "jose-jwe-inspect"
  )
}

// ---------------------------------------------------------------------------
// JwsAlgorithm enum field accesses (signing/MAC algorithms)
// ---------------------------------------------------------------------------
predicate isJwsAlgorithmDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "JwsAlgorithm"
  |
    fa.getTarget().getName() = "none"   and algo = "none"   or
    fa.getTarget().getName() = "HS256"  and algo = "hs256"  or
    fa.getTarget().getName() = "HS384"  and algo = "hs384"  or
    fa.getTarget().getName() = "HS512"  and algo = "hs512"  or
    fa.getTarget().getName() = "RS256"  and algo = "rs256"  or
    fa.getTarget().getName() = "RS384"  and algo = "rs384"  or
    fa.getTarget().getName() = "RS512"  and algo = "rs512"  or
    fa.getTarget().getName() = "PS256"  and algo = "ps256"  or
    fa.getTarget().getName() = "PS384"  and algo = "ps384"  or
    fa.getTarget().getName() = "PS512"  and algo = "ps512"  or
    fa.getTarget().getName() = "ES256"  and algo = "es256"  or
    fa.getTarget().getName() = "ES384"  and algo = "es384"  or
    fa.getTarget().getName() = "ES512"  and algo = "es512"
    // Note: jose-jwt has no ES256K/secp256k1 support (verified against the library
    // source) — JwsAlgorithm has no ES256K member, unlike Microsoft.IdentityModel.
  )
}

// ---------------------------------------------------------------------------
// JweAlgorithm enum field accesses (JWE key management algorithms)
// ---------------------------------------------------------------------------
predicate isJweAlgorithmDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "JweAlgorithm"
  |
    fa.getTarget().getName() = "RSA1_5"             and algo = "rsa-1_5"           or
    fa.getTarget().getName() = "RSA_OAEP"           and algo = "rsa-oaep"          or
    fa.getTarget().getName() = "RSA_OAEP_256"       and algo = "rsa-oaep-256"      or
    fa.getTarget().getName() = "RSA_OAEP_384"       and algo = "rsa-oaep-384"      or
    fa.getTarget().getName() = "RSA_OAEP_512"       and algo = "rsa-oaep-512"      or
    fa.getTarget().getName() = "DIR"                and algo = "direct"            or
    fa.getTarget().getName() = "A128KW"             and algo = "aes-128-kw"        or
    fa.getTarget().getName() = "A192KW"             and algo = "aes-192-kw"        or
    fa.getTarget().getName() = "A256KW"             and algo = "aes-256-kw"        or
    fa.getTarget().getName() = "A128GCMKW"          and algo = "aes-128-gcm-kw"   or
    fa.getTarget().getName() = "A192GCMKW"          and algo = "aes-192-gcm-kw"   or
    fa.getTarget().getName() = "A256GCMKW"          and algo = "aes-256-gcm-kw"   or
    fa.getTarget().getName() = "ECDH_ES"            and algo = "ecdh-es"           or
    fa.getTarget().getName() = "ECDH_ES_A128KW"     and algo = "ecdh-es-a128kw"   or
    fa.getTarget().getName() = "ECDH_ES_A192KW"     and algo = "ecdh-es-a192kw"   or
    fa.getTarget().getName() = "ECDH_ES_A256KW"     and algo = "ecdh-es-a256kw"   or
    fa.getTarget().getName() = "PBES2_HS256_A128KW" and algo = "pbes2-hs256-a128kw" or
    fa.getTarget().getName() = "PBES2_HS384_A192KW" and algo = "pbes2-hs384-a192kw" or
    fa.getTarget().getName() = "PBES2_HS512_A256KW" and algo = "pbes2-hs512-a256kw"
  )
}

// ---------------------------------------------------------------------------
// JweEncryption enum field accesses (JWE content encryption algorithms)
// ---------------------------------------------------------------------------
predicate isJweEncryptionDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "JweEncryption"
  |
    fa.getTarget().getName() = "A128CBC_HS256" and algo = "aes-128-cbc-hs256" or
    fa.getTarget().getName() = "A192CBC_HS384" and algo = "aes-192-cbc-hs384" or
    fa.getTarget().getName() = "A256CBC_HS512" and algo = "aes-256-cbc-hs512" or
    fa.getTarget().getName() = "A128GCM"       and algo = "aes-128-gcm"       or
    fa.getTarget().getName() = "A192GCM"       and algo = "aes-192-gcm"       or
    fa.getTarget().getName() = "A256GCM"       and algo = "aes-256-gcm"
  )
}

// ---------------------------------------------------------------------------
// JwtSettings — global or per-call registration of custom algorithm handlers
// ---------------------------------------------------------------------------
predicate isJwtSettingsDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "JwtSettings" and
    mc.getTarget().getName() =
      ["RegisterJws", "RegisterJwe", "RegisterJwa", "RegisterMapper", "RegisterJwsAlias",
       "RegisterJweAlias", "RegisterJwaAlias", "DeregisterJws", "DeregisterJwe", "DeregisterJwa"] and
    algo = "jose-jwt-custom-algorithm"
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "JwtSettings" and
    algo = "jose-jwt-settings"
  )
}

// ---------------------------------------------------------------------------
// JWK / JWKS key material
// ---------------------------------------------------------------------------
predicate isJwkDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "Jwk" and
    algo = "jwk"
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "JwkSet" and
    algo = "jwks"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getDeclaringType().getName() = ["Jwk", "JwkSet"] and
    mc.getTarget().getName() = "FromJson" and
    algo = "jwk"
  )
}

// =============================================================================
// Main query
// =============================================================================

from Expr call, string algo, string api
where
  api = "Jose.JWT" and
  not call.getFile().getBaseName() = ["_cbom_type_stubs.cs", "type-stubs.cs"] and
  (
    isJwtOperationDetection(call, algo) or
    isJweJsonOperationDetection(call, algo) or
    isJwsAlgorithmDetection(call, algo) or
    isJweAlgorithmDetection(call, algo) or
    isJweEncryptionDetection(call, algo) or
    isJwtSettingsDetection(call, algo) or
    isJwkDetection(call, algo)
  )
select call, "algo=" + algo + ", api=" + api
