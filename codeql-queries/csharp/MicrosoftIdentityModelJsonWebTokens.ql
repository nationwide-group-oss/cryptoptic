/**
 * @name Crypto inventory — Microsoft.IdentityModel.JsonWebTokens (C#/.NET)
 * @description Inventory of Microsoft.IdentityModel.JsonWebTokens usage:
 *              JsonWebTokenHandler operations (create, validate, read), security key
 *              construction (SymmetricSecurityKey, RsaSecurityKey, ECDsaSecurityKey,
 *              JsonWebKey), signing and encrypting credentials, and SecurityAlgorithms
 *              algorithm identifier constants.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/csharp-cbom-microsoft-identity-model-jwt
 * @tags security
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow

// Note: namespace guards are intentionally omitted — in --build-mode=none,
// NuGet types (Microsoft.IdentityModel.JsonWebTokens, Microsoft.IdentityModel.Tokens)
// are unresolved so getNamespace().getFullName() returns "".

// =============================================================================
// Algorithm string resolution — SecurityAlgorithms.* field or string literal
// =============================================================================

/** Maps a `Microsoft.IdentityModel.Tokens.SecurityAlgorithms` field name to a canonical label. */
private predicate securityAlgorithmName(string field, string algo) {
  field = "HmacSha256" and algo = "hs256" or
  field = "HmacSha384" and algo = "hs384" or
  field = "HmacSha512" and algo = "hs512" or
  field = "RsaSha256" and algo = "rs256" or
  field = "RsaSha384" and algo = "rs384" or
  field = "RsaSha512" and algo = "rs512" or
  field = "RsaSsaPssSha256" and algo = "ps256" or
  field = "RsaSsaPssSha384" and algo = "ps384" or
  field = "RsaSsaPssSha512" and algo = "ps512" or
  field = "EcdsaSha256" and algo = "es256" or
  field = "EcdsaSha384" and algo = "es384" or
  field = "EcdsaSha512" and algo = "es512" or
  // Note: SecurityAlgorithms has no EdDsa or EcdsaSha256K constants in the real
  // library (verified against source) — EdDSA/ES256K are only reachable as raw
  // string literals, handled by securityAlgorithmLiteral below.
  field = "None"     and algo = "none"  or
  field = "Aes128KW" and algo = "a128kw" or
  field = "Aes192KW" and algo = "a192kw" or
  field = "Aes256KW" and algo = "a256kw" or
  field = "RsaOAEP"    and algo = "rsa-oaep"     or
  field = "RsaOAEP256" and algo = "rsa-oaep-256" or
  field = "RsaPKCS1"   and algo = "rsa-pkcs1v15" or
  field = "EcdhEs"        and algo = "ecdh-es"        or
  field = "EcdhEsA128kw"  and algo = "ecdh-es-a128kw" or
  field = "EcdhEsA192kw"  and algo = "ecdh-es-a192kw" or
  field = "EcdhEsA256kw"  and algo = "ecdh-es-a256kw" or
  field = "Aes128CbcHmacSha256" and algo = "a128cbc-hs256" or
  field = "Aes192CbcHmacSha384" and algo = "a192cbc-hs384" or
  field = "Aes256CbcHmacSha512" and algo = "a256cbc-hs512" or
  field = "Aes128Gcm" and algo = "a128gcm" or
  field = "Aes192Gcm" and algo = "a192gcm" or
  field = "Aes256Gcm" and algo = "a256gcm" or
  field = "MlDsa44" and algo = "ml-dsa-44" or
  field = "MlDsa65" and algo = "ml-dsa-65" or
  field = "MlDsa87" and algo = "ml-dsa-87" or
  field = "Aes128Encryption" and algo = "aes-128-cbc" or
  field = "Aes192Encryption" and algo = "aes-192-cbc" or
  field = "Aes256Encryption" and algo = "aes-256-cbc" or
  field = "DesEncryption" and algo = "des-cbc" or
  field = "Aes128KeyWrap" and algo = "xml-aes-128-kw" or
  field = "Aes192KeyWrap" and algo = "xml-aes-192-kw" or
  field = "Aes256KeyWrap" and algo = "xml-aes-256-kw" or
  field = "RsaV15KeyWrap" and algo = "rsa-pkcs1v15" or
  field = "RsaOaepKeyWrap" and algo = "rsa-oaep" or
  field = "Ripemd160Digest" and algo = "ripemd160" or
  field = "ExclusiveC14n" and algo = "xml-exclusive-c14n" or
  field = "ExclusiveC14nWithComments" and algo = "xml-exclusive-c14n-comments" or
  field = "EnvelopedSignature" and algo = "xml-enveloped-signature" or
  field = "EcdsaSha256Signature" and algo = "xml-ecdsa-sha256" or
  field = "EcdsaSha384Signature" and algo = "xml-ecdsa-sha384" or
  field = "EcdsaSha512Signature" and algo = "xml-ecdsa-sha512" or
  field = "RsaSha256Signature" and algo = "xml-rsa-sha256" or
  field = "RsaSha384Signature" and algo = "xml-rsa-sha384" or
  field = "RsaSha512Signature" and algo = "xml-rsa-sha512" or
  field = "RsaSsaPssSha256Signature" and algo = "xml-rsa-pss-sha256" or
  field = "RsaSsaPssSha384Signature" and algo = "xml-rsa-pss-sha384" or
  field = "RsaSsaPssSha512Signature" and algo = "xml-rsa-pss-sha512" or
  field = "HmacSha256Signature" and algo = "xml-hmac-sha256" or
  field = "HmacSha384Signature" and algo = "xml-hmac-sha384" or
  field = "HmacSha512Signature" and algo = "xml-hmac-sha512" or
  // Digest-only identifiers, used for `SecurityKey` digests and JWK thumbprints
  field = ["Sha256", "Sha256Digest"] and algo = "sha256" or
  field = ["Sha384", "Sha384Digest"] and algo = "sha384" or
  field = ["Sha512", "Sha512Digest"] and algo = "sha512"
}

/** Maps an RFC 7518 compact algorithm identifier string to a canonical label. */
private predicate securityAlgorithmLiteral(string lit, string algo) {
  lit = "HS256" and algo = "hs256" or lit = "HS384" and algo = "hs384" or
  lit = "HS512" and algo = "hs512" or lit = "RS256" and algo = "rs256" or
  lit = "RS384" and algo = "rs384" or lit = "RS512" and algo = "rs512" or
  lit = "PS256" and algo = "ps256" or lit = "PS384" and algo = "ps384" or
  lit = "PS512" and algo = "ps512" or lit = "ES256" and algo = "es256" or
  lit = "ES384" and algo = "es384" or lit = "ES512" and algo = "es512" or
  lit = "ES256K" and algo = "es256k" or lit = "EdDSA" and algo = "eddsa" or
  lit = "none" and algo = "none" or
  lit = "A128KW" and algo = "a128kw" or lit = "A192KW" and algo = "a192kw" or
  lit = "A256KW" and algo = "a256kw" or
  lit = "RSA-OAEP" and algo = "rsa-oaep" or
  lit = "RSA-OAEP-256" and algo = "rsa-oaep-256" or
  lit = "RSA1_5" and algo = "rsa-pkcs1v15" or
  lit = "dir" and algo = "direct" or
  lit = "ECDH-ES" and algo = "ecdh-es" or
  lit = "ECDH-ES+A128KW" and algo = "ecdh-es-a128kw" or
  lit = "ECDH-ES+A192KW" and algo = "ecdh-es-a192kw" or
  lit = "ECDH-ES+A256KW" and algo = "ecdh-es-a256kw" or
  lit = "A128CBC-HS256" and algo = "a128cbc-hs256" or
  lit = "A192CBC-HS384" and algo = "a192cbc-hs384" or
  lit = "A256CBC-HS512" and algo = "a256cbc-hs512" or
  lit = "A128GCM" and algo = "a128gcm" or lit = "A192GCM" and algo = "a192gcm" or
  lit = "A256GCM" and algo = "a256gcm" or
  lit = "ML-DSA-44" and algo = "ml-dsa-44" or
  lit = "ML-DSA-65" and algo = "ml-dsa-65" or
  lit = "ML-DSA-87" and algo = "ml-dsa-87" or
  lit = "http://www.w3.org/2001/04/xmlenc#aes128-cbc" and algo = "aes-128-cbc" or
  lit = "http://www.w3.org/2001/04/xmlenc#aes192-cbc" and algo = "aes-192-cbc" or
  lit = "http://www.w3.org/2001/04/xmlenc#aes256-cbc" and algo = "aes-256-cbc" or
  lit = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc" and algo = "des-cbc" or
  lit = "http://www.w3.org/2001/04/xmlenc#kw-aes128" and algo = "xml-aes-128-kw" or
  lit = "http://www.w3.org/2001/04/xmlenc#kw-aes192" and algo = "xml-aes-192-kw" or
  lit = "http://www.w3.org/2001/04/xmlenc#kw-aes256" and algo = "xml-aes-256-kw" or
  lit = "http://www.w3.org/2001/04/xmlenc#rsa-1_5" and algo = "rsa-pkcs1v15" or
  lit = "http://www.w3.org/2001/04/xmlenc#rsa-oaep" and algo = "rsa-oaep" or
  lit = "http://www.w3.org/2001/04/xmlenc#ripemd160" and algo = "ripemd160" or
  lit = "http://www.w3.org/2001/10/xml-exc-c14n#" and algo = "xml-exclusive-c14n" or
  lit = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" and algo = "xml-exclusive-c14n-comments" or
  lit = "http://www.w3.org/2000/09/xmldsig#enveloped-signature" and algo = "xml-enveloped-signature" or
  lit = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" and algo = "xml-ecdsa-sha256" or
  lit = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" and algo = "xml-ecdsa-sha384" or
  lit = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" and algo = "xml-ecdsa-sha512" or
  lit = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" and algo = "xml-rsa-sha256" or
  lit = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" and algo = "xml-rsa-sha384" or
  lit = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" and algo = "xml-rsa-sha512" or
  lit = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256" and algo = "xml-hmac-sha256" or
  lit = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384" and algo = "xml-hmac-sha384" or
  lit = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512" and algo = "xml-hmac-sha512"
}

private predicate algoDirect(Expr arg, string algo) {
  exists(string field |
    arg.(FieldAccess).getTarget().getDeclaringType().getName() = "SecurityAlgorithms" and
    field = arg.(FieldAccess).getTarget().getName() and
    securityAlgorithmName(field, algo)
  )
  or
  securityAlgorithmLiteral(arg.(StringLiteral).getValue(), algo)
}

private predicate algoArg(Expr arg, string algo) {
  algoDirect(arg, algo)
  or
  exists(Expr src |
    src != arg and
    algoDirect(src, algo) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

// =============================================================================
// Detection predicates
// =============================================================================

// ---------------------------------------------------------------------------
// JsonWebTokenHandler — async-first handler (Microsoft.IdentityModel.JsonWebTokens)
// ---------------------------------------------------------------------------
private predicate isJsonWebTokenHandlerDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "JsonWebTokenHandler"
  |
    mc.getTarget().getName() = ["CreateToken", "CreateTokenAsync"]
      and algo = "jwt-create"
    or
    mc.getTarget().getName() = ["ValidateToken", "ValidateTokenAsync"]
      and algo = "jwt-validate"
    or
    mc.getTarget().getName() = ["ReadJsonWebToken", "ReadToken"]
      and algo = "jwt-read"
    or
    mc.getTarget().getName() = "CanReadToken"
      and algo = "jwt-read"
  )
}

// ---------------------------------------------------------------------------
// SigningCredentials construction
// ---------------------------------------------------------------------------
private predicate isSigningCredentialsDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "SigningCredentials"
  |
    exists(string a, string d |
      algoArg(oc.getArgument(1), a) and
      algoArg(oc.getArgument(2), d) and
      algo = "jwt-signing-" + a + "-digest-" + d
    )
    or
    exists(string a | algoArg(oc.getArgument(1), a) and algo = "jwt-signing-" + a)
    and not exists(string d | algoArg(oc.getArgument(2), d))
    or
    not exists(string a | algoArg(oc.getArgument(1), a)) and
    not exists(string d | algoArg(oc.getArgument(2), d)) and
    algo = "jwt-signing-credentials"
  )
}

// ---------------------------------------------------------------------------
// EncryptingCredentials construction
// ---------------------------------------------------------------------------
private predicate isEncryptingCredentialsDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "EncryptingCredentials"
  |
    exists(string kw, string enc |
      algoArg(oc.getArgument(1), kw) and
      algoArg(oc.getArgument(2), enc) and
      algo = "jwt-jwe-" + kw + "-" + enc
    )
    or
    exists(string kw |
      algoArg(oc.getArgument(1), kw) and
      not exists(string enc | algoArg(oc.getArgument(2), enc)) and
      algo = "jwt-jwe-" + kw
    )
    or
    exists(string enc |
      algoArg(oc.getArgument(2), enc) and
      not exists(string kw | algoArg(oc.getArgument(1), kw)) and
      algo = "jwt-jwe-enc-" + enc
    )
    or
    not (
      exists(string kw | algoArg(oc.getArgument(1), kw)) and
      exists(string enc | algoArg(oc.getArgument(2), enc))
    ) and
    algo = "jwt-encrypting-credentials"
  )
}

// ---------------------------------------------------------------------------
// Security key constructors
// ---------------------------------------------------------------------------
private predicate isSecurityKeyDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "SymmetricSecurityKey" and
    algo = "symmetric-key"
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "RsaSecurityKey" and
    algo = "rsa-key"
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "ECDsaSecurityKey" and
    algo = "ecdsa-key"
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "X509SecurityKey" and
    algo = "x509-key"
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "JsonWebKey" and
    algo = "jwk"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Create" and
    mc.getTarget().getDeclaringType().getName() = "JsonWebKeySet" and
    algo = "jwks"
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "JsonWebKeySet" and
    algo = "jwks"
  )
}

// ---------------------------------------------------------------------------
// SecurityAlgorithms constant field reads
// ---------------------------------------------------------------------------
private predicate isSecurityAlgorithmsDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "SecurityAlgorithms" and
    securityAlgorithmName(fa.getTarget().getName(), algo)
  )
}

// ---------------------------------------------------------------------------
// Lower-level Microsoft.IdentityModel cryptographic providers
// ---------------------------------------------------------------------------
private predicate isCryptoProviderDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "CryptoProviderFactory"
  |
    mc.getTarget().getName() = "CreateForSigning" and algo = "jwt-provider-signing" or
    mc.getTarget().getName() = "CreateForVerifying" and algo = "jwt-provider-verifying" or
    mc.getTarget().getName() = "CreateKeyWrapProviderForWrapping" and algo = "jwt-provider-key-wrap" or
    mc.getTarget().getName() = "CreateKeyWrapProviderForUnwrapping" and algo = "jwt-provider-key-unwrap" or
    mc.getTarget().getName() = "CreateAuthenticatedEncryptionProvider" and algo = "jwt-provider-authenticated-encryption" or
    mc.getTarget().getName() = "CreateHashAlgorithm" and algo = "jwt-provider-hash"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "SignatureProvider"
  |
    mc.getTarget().getName() = "Sign" and algo = "jwt-sign" or
    mc.getTarget().getName() = "Verify" and algo = "jwt-verify"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "KeyWrapProvider"
  |
    mc.getTarget().getName() = "WrapKey" and algo = "jwt-key-wrap" or
    mc.getTarget().getName() = "UnwrapKey" and algo = "jwt-key-unwrap"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "AuthenticatedEncryptionProvider"
  |
    mc.getTarget().getName() = "Encrypt" and algo = "jwt-authenticated-encrypt" or
    mc.getTarget().getName() = "Decrypt" and algo = "jwt-authenticated-decrypt"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "HashAlgorithmProvider" and
    mc.getTarget().getName() = ["CreateHash", "Hash"] and
    algo = "jwt-hash"
  )
}

// =============================================================================
// Select
// =============================================================================

from Expr call, string algo, string api
where
  api = "Microsoft.IdentityModel.JsonWebTokens" and
  not call.getFile().getBaseName() = ["_cbom_type_stubs.cs", "type-stubs.cs"] and
  (
    isJsonWebTokenHandlerDetection(call, algo)   or
    isSigningCredentialsDetection(call, algo)    or
    isEncryptingCredentialsDetection(call, algo) or
    isSecurityKeyDetection(call, algo)           or
    isSecurityAlgorithmsDetection(call, algo)    or
    isCryptoProviderDetection(call, algo)
  )
select call, "algo=" + algo + ", api=" + api
