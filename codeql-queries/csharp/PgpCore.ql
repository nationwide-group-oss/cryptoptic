/**
 * @name Crypto inventory — PgpCore (C#/.NET)
 * @description Inventory of PgpCore (mattosaurus/PgpCore NuGet) OpenPGP API usage:
 *              PGP operations (encrypt, decrypt, sign, verify, keygen, inspect),
 *              and algorithm configuration via SymmetricKeyAlgorithmTag,
 *              HashAlgorithmTag, and PublicKeyAlgorithmTag.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/csharp-cbom-pgpcore
 * @tags security
 */

import csharp

// Note: namespace guards are intentionally omitted for algorithm enum detections.
// In --build-mode=none, NuGet types (PgpCore, Org.BouncyCastle.Bcpg) are unresolved
// so getNamespace().getFullName() returns "". Detection relies on distinctive type names.

// =============================================================================
// PGP operations — all methods on the PgpCore.PGP class
// =============================================================================

/**
 * Holds for method calls on the `PGP` class that perform cryptographic operations.
 * Both sync and async forms are matched (e.g. `Encrypt` and `EncryptAsync`).
 */
predicate isPgpOperationDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "PGP"
  |
    mc.getTarget().getName() = ["Encrypt", "EncryptAsync"]
      and algo = "pgp-encrypt"
    or
    mc.getTarget().getName() = ["Sign", "SignAsync"]
      and algo = "pgp-sign"
    or
    mc.getTarget().getName() = ["ClearSign", "ClearSignAsync"]
      and algo = "pgp-clear-sign"
    or
    mc.getTarget().getName() = ["SignDetached", "SignDetachedAsync"]
      and algo = "pgp-sign-detached"
    or
    mc.getTarget().getName() = ["VerifyDetached", "VerifyDetachedAsync"]
      and algo = "pgp-verify-detached"
    or
    mc.getTarget().getName() = ["EncryptAndSign", "EncryptAndSignAsync"]
      and algo = "pgp-encrypt-sign"
    or
    mc.getTarget().getName() = ["Decrypt", "DecryptAsync"]
      and algo = "pgp-decrypt"
    or
    mc.getTarget().getName() = ["Verify", "VerifyAsync"]
      and algo = "pgp-verify"
    or
    mc.getTarget().getName() = ["VerifyClear", "VerifyClearAsync",
                   "VerifyAndReadClearArmoredString",
                   "VerifyAndReadClearArmoredStringAsync"]
      and algo = "pgp-verify-clear"
    or
    mc.getTarget().getName() = ["DecryptAndVerify", "DecryptAndVerifyAsync"]
      and algo = "pgp-decrypt-verify"
    or
    mc.getTarget().getName() = ["Inspect", "InspectAsync"]
      and algo = "pgp-inspect"
    or
    mc.getTarget().getName() = ["GenerateKey", "GenerateKeyAsync"]
      and algo = "pgp-keygen"
    or
    // GetRecipients — inspect key ids a message is encrypted to
    mc.getTarget().getName() = ["GetRecipients", "GetRecipientsAsync"]
      and algo = "pgp-get-recipients"
  )
}

// =============================================================================
// SymmetricKeyAlgorithmTag — session key cipher for PGP encryption
// (from Org.BouncyCastle.Bcpg, set via PGP.SymmetricKeyAlgorithm)
// =============================================================================
predicate isPgpSymmetricAlgoDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "SymmetricKeyAlgorithmTag"
  |
    fa.getTarget().getName() = "Null"        and algo = "pgp-sym-null"         or
    fa.getTarget().getName() = "Idea"        and algo = "pgp-sym-idea"         or
    fa.getTarget().getName() = "TripleDes"   and algo = "pgp-sym-3des"         or
    fa.getTarget().getName() = "Cast5"       and algo = "pgp-sym-cast5"        or
    fa.getTarget().getName() = "Blowfish"    and algo = "pgp-sym-blowfish"     or
    fa.getTarget().getName() = "Safer"       and algo = "pgp-sym-safer"        or
    fa.getTarget().getName() = "Des"         and algo = "pgp-sym-des"          or
    fa.getTarget().getName() = "Aes128"      and algo = "pgp-sym-aes-128"      or
    fa.getTarget().getName() = "Aes192"      and algo = "pgp-sym-aes-192"      or
    fa.getTarget().getName() = "Aes256"      and algo = "pgp-sym-aes-256"      or
    fa.getTarget().getName() = "Twofish"     and algo = "pgp-sym-twofish"      or
    fa.getTarget().getName() = "Camellia128" and algo = "pgp-sym-camellia-128" or
    fa.getTarget().getName() = "Camellia192" and algo = "pgp-sym-camellia-192" or
    fa.getTarget().getName() = "Camellia256" and algo = "pgp-sym-camellia-256"
  )
}

// =============================================================================
// HashAlgorithmTag — digest used for signatures and key self-certification
// (from Org.BouncyCastle.Bcpg, set via PGP.HashAlgorithmTag)
// =============================================================================
predicate isPgpHashAlgoDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "HashAlgorithmTag"
  |
    fa.getTarget().getName() = "MD5"         and algo = "md5"       or
    fa.getTarget().getName() = "Sha1"        and algo = "sha1"      or
    fa.getTarget().getName() = "RipeMD160"   and algo = "ripemd160" or
    fa.getTarget().getName() = "DoubleSha"   and algo = "double-sha" or
    fa.getTarget().getName() = "MD2"         and algo = "md2"       or
    fa.getTarget().getName() = "Tiger192"    and algo = "tiger192"  or
    fa.getTarget().getName() = "Sha256"      and algo = "sha256"    or
    fa.getTarget().getName() = "Sha384"      and algo = "sha384"    or
    fa.getTarget().getName() = "Sha512"      and algo = "sha512"    or
    fa.getTarget().getName() = "Sha224"        and algo = "sha224"        or
    fa.getTarget().getName() = "Haval5pass160" and algo = "haval5pass160" or
    fa.getTarget().getName() = "MD4"           and algo = "md4"           or
    fa.getTarget().getName() = "Sha3_224"      and algo = "sha3-224"      or
    fa.getTarget().getName() = "Sha3_256"      and algo = "sha3-256"      or
    fa.getTarget().getName() = "Sha3_384"      and algo = "sha3-384"      or
    fa.getTarget().getName() = "Sha3_512"      and algo = "sha3-512"      or
    fa.getTarget().getName() = "Sha3_256_Old"  and algo = "sha3-256-old"  or
    fa.getTarget().getName() = "Sha3_512_Old"  and algo = "sha3-512-old"  or
    fa.getTarget().getName() = "SM3"           and algo = "sm3"
  )
}

// =============================================================================
// PublicKeyAlgorithmTag — asymmetric algorithm for signing / key generation
// (from Org.BouncyCastle.Bcpg, set via PGP.PublicKeyAlgorithm)
// =============================================================================
predicate isPgpPublicKeyAlgoDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "PublicKeyAlgorithmTag"
  |
    fa.getTarget().getName() = "RsaGeneral"     and algo = "rsa"         or
    fa.getTarget().getName() = "RsaEncrypt"     and algo = "rsa"         or
    fa.getTarget().getName() = "RsaSign"        and algo = "rsa"         or
    fa.getTarget().getName() = "ElGamalEncrypt" and algo = "elgamal"     or
    fa.getTarget().getName() = "ElGamalGeneral" and algo = "elgamal"     or
    fa.getTarget().getName() = "Dsa"            and algo = "dsa"         or
    fa.getTarget().getName() = "ECDH"           and algo = "ecdh"        or
    fa.getTarget().getName() = "ECDsa"          and algo = "ecdsa"       or
    fa.getTarget().getName() = "DiffieHellman"  and algo = "dh"          or
    fa.getTarget().getName() = ["EdDsa", "EdDsa_Legacy"] and algo = "eddsa" or
    fa.getTarget().getName() = "Ed25519"        and algo = "ed25519"     or
    fa.getTarget().getName() = "Ed448"          and algo = "ed448"       or
    fa.getTarget().getName() = "X25519"         and algo = "x25519"      or
    fa.getTarget().getName() = "X448"           and algo = "x448"
  )
}

// =============================================================================
// CompressionAlgorithmTag — compression applied before encryption/signing
// =============================================================================
predicate isPgpCompressionAlgoDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "CompressionAlgorithmTag"
  |
    fa.getTarget().getName() = "Uncompressed" and algo = "pgp-compression-none" or
    fa.getTarget().getName() = "Zip"         and algo = "pgp-compression-zip"  or
    fa.getTarget().getName() = "ZLib"        and algo = "pgp-compression-zlib" or
    fa.getTarget().getName() = "BZip2"       and algo = "pgp-compression-bzip2"
  )
}

// =============================================================================
// AeadAlgorithmTag — AEAD mode for OpenPGP v5/v6 encrypted data packets
// =============================================================================
predicate isPgpAeadAlgoDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "AeadAlgorithmTag"
  |
    fa.getTarget().getName() = "Eax" and algo = "pgp-aead-eax" or
    fa.getTarget().getName() = "Ocb" and algo = "pgp-aead-ocb" or
    fa.getTarget().getName() = "Gcm" and algo = "pgp-aead-gcm"
  )
}

// =============================================================================
// EncryptionKeys — binds the public/private key material used by a PGP operation
// =============================================================================
predicate isPgpEncryptionKeysDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "EncryptionKeys" and
    algo = "pgp-keys"
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "PGP" and
    algo = "pgp-context"
  )
}

// =============================================================================
// Select
// =============================================================================

from Expr call, string algo, string api
where
  api = "PgpCore" and
  not call.getFile().getBaseName() = ["_cbom_type_stubs.cs", "type-stubs.cs"] and
  (
    isPgpOperationDetection(call, algo)       or
    isPgpSymmetricAlgoDetection(call, algo)   or
    isPgpHashAlgoDetection(call, algo)        or
    isPgpCompressionAlgoDetection(call, algo) or
    isPgpPublicKeyAlgoDetection(call, algo)   or
    isPgpAeadAlgoDetection(call, algo)        or
    isPgpEncryptionKeysDetection(call, algo)
  )
select call, "algo=" + algo + ", api=" + api
