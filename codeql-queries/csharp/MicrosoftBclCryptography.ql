/**
 * @name Crypto inventory — Microsoft.Bcl.Cryptography (C#/.NET)
 * @description Inventory of Microsoft.Bcl.Cryptography usage: ML-DSA (FIPS 204),
 *              ML-KEM (FIPS 203), SLH-DSA (FIPS 205), Composite ML-DSA post-quantum
 *              algorithms, and SP 800-108 HMAC counter-mode KDF.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/csharp-cbom-microsoft-bcl-cryptography
 * @tags security
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow

// Note: ML-DSA / ML-KEM / SLH-DSA / CompositeMLDsa types are in .NET 10+
// and are unresolved NuGet types when the project targets net8.0.
// SP800108HmacCounterKdf is in .NET 7+ BCL; it resolves without stubs.
// No namespace guards are used for any type — unresolved types return "" from
// getNamespace().getFullName() in --build-mode=none.

// =============================================================================
// Algorithm identifier resolution helpers (via static property access)
// =============================================================================

// MLDsaAlgorithm.MLDsa44 / MLDsa65 / MLDsa87
private predicate mlDsaAlgoDirect(Expr arg, string algo) {
  arg.(PropertyAccess).getTarget().getDeclaringType().getName() = "MLDsaAlgorithm" and (
    arg.(PropertyAccess).getTarget().getName() = "MLDsa44" and algo = "ml-dsa-44" or
    arg.(PropertyAccess).getTarget().getName() = "MLDsa65" and algo = "ml-dsa-65" or
    arg.(PropertyAccess).getTarget().getName() = "MLDsa87" and algo = "ml-dsa-87"
  )
}

private predicate mlDsaAlgoArg(Expr arg, string algo) {
  mlDsaAlgoDirect(arg, algo)
  or
  exists(Expr src |
    src != arg and mlDsaAlgoDirect(src, algo) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

// MLKemAlgorithm.MLKem512 / MLKem768 / MLKem1024
private predicate mlKemAlgoDirect(Expr arg, string algo) {
  arg.(PropertyAccess).getTarget().getDeclaringType().getName() = "MLKemAlgorithm" and (
    arg.(PropertyAccess).getTarget().getName() = "MLKem512"  and algo = "ml-kem-512"  or
    arg.(PropertyAccess).getTarget().getName() = "MLKem768"  and algo = "ml-kem-768"  or
    arg.(PropertyAccess).getTarget().getName() = "MLKem1024" and algo = "ml-kem-1024"
  )
}

private predicate mlKemAlgoArg(Expr arg, string algo) {
  mlKemAlgoDirect(arg, algo)
  or
  exists(Expr src |
    src != arg and mlKemAlgoDirect(src, algo) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

// SlhDsaAlgorithm.SlhDsaSha2_*/SlhDsaShake* — 12 FIPS 205 parameter sets
private predicate slhDsaAlgoDirect(Expr arg, string algo) {
  arg.(PropertyAccess).getTarget().getDeclaringType().getName() = "SlhDsaAlgorithm" and (
    arg.(PropertyAccess).getTarget().getName() = "SlhDsaSha2_128s"  and algo = "slh-dsa-sha2-128s"  or
    arg.(PropertyAccess).getTarget().getName() = "SlhDsaSha2_128f"  and algo = "slh-dsa-sha2-128f"  or
    arg.(PropertyAccess).getTarget().getName() = "SlhDsaSha2_192s"  and algo = "slh-dsa-sha2-192s"  or
    arg.(PropertyAccess).getTarget().getName() = "SlhDsaSha2_192f"  and algo = "slh-dsa-sha2-192f"  or
    arg.(PropertyAccess).getTarget().getName() = "SlhDsaSha2_256s"  and algo = "slh-dsa-sha2-256s"  or
    arg.(PropertyAccess).getTarget().getName() = "SlhDsaSha2_256f"  and algo = "slh-dsa-sha2-256f"  or
    arg.(PropertyAccess).getTarget().getName() = "SlhDsaShake128s"  and algo = "slh-dsa-shake-128s" or
    arg.(PropertyAccess).getTarget().getName() = "SlhDsaShake128f"  and algo = "slh-dsa-shake-128f" or
    arg.(PropertyAccess).getTarget().getName() = "SlhDsaShake192s"  and algo = "slh-dsa-shake-192s" or
    arg.(PropertyAccess).getTarget().getName() = "SlhDsaShake192f"  and algo = "slh-dsa-shake-192f" or
    arg.(PropertyAccess).getTarget().getName() = "SlhDsaShake256s"  and algo = "slh-dsa-shake-256s" or
    arg.(PropertyAccess).getTarget().getName() = "SlhDsaShake256f"  and algo = "slh-dsa-shake-256f"
  )
}

private predicate slhDsaAlgoArg(Expr arg, string algo) {
  slhDsaAlgoDirect(arg, algo)
  or
  exists(Expr src |
    src != arg and slhDsaAlgoDirect(src, algo) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

// HashAlgorithmName static property for SP800108HmacCounterKdf constructor
private predicate hashAlgoNameDirect(Expr arg, string algo) {
  arg.(PropertyAccess).getTarget().getDeclaringType().getName() = "HashAlgorithmName" and (
    arg.(PropertyAccess).getTarget().getName() = "SHA256"   and algo = "sp800-108-hmac-sha256"    or
    arg.(PropertyAccess).getTarget().getName() = "SHA384"   and algo = "sp800-108-hmac-sha384"    or
    arg.(PropertyAccess).getTarget().getName() = "SHA512"   and algo = "sp800-108-hmac-sha512"    or
    arg.(PropertyAccess).getTarget().getName() = "SHA3_256" and algo = "sp800-108-hmac-sha3-256"  or
    arg.(PropertyAccess).getTarget().getName() = "SHA3_384" and algo = "sp800-108-hmac-sha3-384"  or
    arg.(PropertyAccess).getTarget().getName() = "SHA3_512" and algo = "sp800-108-hmac-sha3-512"  or
    arg.(PropertyAccess).getTarget().getName() = "SHA1"     and algo = "sp800-108-hmac-sha1"      or
    arg.(PropertyAccess).getTarget().getName() = "MD5"      and algo = "sp800-108-hmac-md5"
  )
}

private predicate hashAlgoNameArg(Expr arg, string algo) {
  hashAlgoNameDirect(arg, algo)
  or
  exists(Expr src |
    src != arg and hashAlgoNameDirect(src, algo) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

// =============================================================================
// Detection predicates
// =============================================================================

// ---------------------------------------------------------------------------
// ML-DSA (FIPS 204, CRYSTALS-Dilithium) — post-quantum digital signature
// ---------------------------------------------------------------------------
private predicate isMlDsaDetection(Expr call, string algo) {
  // Static factory: GenerateKey, ImportMLDsaPublicKey, ImportMLDsaPrivateKey,
  // ImportMLDsaPrivateSeed — all take MLDsaAlgorithm as first argument
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "MLDsa" and
    mc.getTarget().getName() = [
      "GenerateKey", "ImportMLDsaPublicKey", "ImportMLDsaPrivateKey", "ImportMLDsaPrivateSeed"
    ]
  |
    exists(string a | mlDsaAlgoArg(mc.getArgument(0), a) and algo = a)
    or
    not exists(string a | mlDsaAlgoArg(mc.getArgument(0), a)) and algo = "ml-dsa"
  )
  or
  // Static/instance: format-based import (no algorithm arg — variant unknown)
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "MLDsa" and
    mc.getTarget().getName() = [
      "ImportSubjectPublicKeyInfo", "ImportPkcs8PrivateKey", "ImportFromPem",
      "ImportEncryptedPkcs8PrivateKey", "ImportFromEncryptedPem"
    ] and
    algo = "ml-dsa"
  )
  or
  // Instance: signing operations
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "MLDsa" and
    mc.getTarget().getName() = ["SignData", "SignPreHash", "SignMu"] and
    algo = "ml-dsa-sign"
  )
  or
  // Instance: verification operations
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "MLDsa" and
    mc.getTarget().getName() = ["VerifyData", "VerifyPreHash", "VerifyMu"] and
    algo = "ml-dsa-verify"
  )
  or
  // Instance: key export
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "MLDsa" and
    mc.getTarget().getName() = [
      "ExportMLDsaPublicKey", "ExportMLDsaPrivateKey", "ExportMLDsaPrivateSeed",
      "TryExportMLDsaPublicKey", "TryExportMLDsaPrivateKey", "TryExportMLDsaPrivateSeed",
      "ExportSubjectPublicKeyInfo", "ExportPkcs8PrivateKey",
      "TryExportSubjectPublicKeyInfo", "TryExportPkcs8PrivateKey",
      "ExportSubjectPublicKeyInfoPem", "ExportPkcs8PrivateKeyPem",
      "ExportEncryptedPkcs8PrivateKey", "ExportEncryptedPkcs8PrivateKeyPem",
      "TryExportEncryptedPkcs8PrivateKey"
    ] and
    algo = "ml-dsa-key-export"
  )
  or
  // MLDsaAlgorithm static property reads
  exists(PropertyAccess pa |
    pa instanceof AssignableRead and
    pa = call and
    pa.getTarget().getDeclaringType().getName() = "MLDsaAlgorithm"
  |
    pa.getTarget().getName() = "MLDsa44" and algo = "ml-dsa-44" or
    pa.getTarget().getName() = "MLDsa65" and algo = "ml-dsa-65" or
    pa.getTarget().getName() = "MLDsa87" and algo = "ml-dsa-87"
  )
}

// ---------------------------------------------------------------------------
// ML-KEM (FIPS 203, CRYSTALS-Kyber) — post-quantum key encapsulation
// ---------------------------------------------------------------------------
private predicate isMlKemDetection(Expr call, string algo) {
  // Static factory: GenerateKey, ImportEncapsulationKey, ImportDecapsulationKey
  // — all take MLKemAlgorithm as first argument
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "MLKem" and
    mc.getTarget().getName() = ["GenerateKey", "ImportEncapsulationKey", "ImportDecapsulationKey", "ImportPrivateSeed"]
  |
    exists(string a | mlKemAlgoArg(mc.getArgument(0), a) and algo = a)
    or
    not exists(string a | mlKemAlgoArg(mc.getArgument(0), a)) and algo = "ml-kem"
  )
  or
  // Static/instance: format-based import
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "MLKem" and
    mc.getTarget().getName() = [
      "ImportSubjectPublicKeyInfo", "ImportPkcs8PrivateKey", "ImportFromPem",
      "ImportEncryptedPkcs8PrivateKey", "ImportFromEncryptedPem"
    ] and
    algo = "ml-kem"
  )
  or
  // Instance: key encapsulation
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "MLKem" and
    mc.getTarget().getName() = "Encapsulate" and
    algo = "ml-kem-encapsulate"
  )
  or
  // Instance: key decapsulation
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "MLKem" and
    mc.getTarget().getName() = "Decapsulate" and
    algo = "ml-kem-decapsulate"
  )
  or
  // Instance: key export
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "MLKem" and
    mc.getTarget().getName() = [
      "ExportEncapsulationKey", "ExportDecapsulationKey",
      "TryExportEncapsulationKey", "TryExportDecapsulationKey",
      "ExportPrivateSeed", "TryExportPrivateSeed",
      "ExportSubjectPublicKeyInfo", "ExportPkcs8PrivateKey",
      "TryExportSubjectPublicKeyInfo", "TryExportPkcs8PrivateKey",
      "ExportSubjectPublicKeyInfoPem", "ExportPkcs8PrivateKeyPem",
      "ExportEncryptedPkcs8PrivateKey", "ExportEncryptedPkcs8PrivateKeyPem",
      "TryExportEncryptedPkcs8PrivateKey"
    ] and
    algo = "ml-kem-key-export"
  )
  or
  // MLKemAlgorithm static property reads
  exists(PropertyAccess pa |
    pa instanceof AssignableRead and
    pa = call and
    pa.getTarget().getDeclaringType().getName() = "MLKemAlgorithm"
  |
    pa.getTarget().getName() = "MLKem512"  and algo = "ml-kem-512"  or
    pa.getTarget().getName() = "MLKem768"  and algo = "ml-kem-768"  or
    pa.getTarget().getName() = "MLKem1024" and algo = "ml-kem-1024"
  )
}

// ---------------------------------------------------------------------------
// SLH-DSA (FIPS 205, SPHINCS+) — post-quantum hash-based digital signature
// ---------------------------------------------------------------------------
private predicate isSlhDsaDetection(Expr call, string algo) {
  // Static factory: GenerateKey, ImportSlhDsaPublicKey, ImportSlhDsaPrivateKey
  // — take SlhDsaAlgorithm as first argument
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "SlhDsa" and
    mc.getTarget().getName() = ["GenerateKey", "ImportSlhDsaPublicKey", "ImportSlhDsaPrivateKey"]
  |
    exists(string a | slhDsaAlgoArg(mc.getArgument(0), a) and algo = a)
    or
    not exists(string a | slhDsaAlgoArg(mc.getArgument(0), a)) and algo = "slh-dsa"
  )
  or
  // Static/instance: format-based import
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "SlhDsa" and
    mc.getTarget().getName() = [
      "ImportSubjectPublicKeyInfo", "ImportPkcs8PrivateKey", "ImportFromPem",
      "ImportEncryptedPkcs8PrivateKey", "ImportFromEncryptedPem"
    ] and
    algo = "slh-dsa"
  )
  or
  // Instance: signing
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "SlhDsa" and
    mc.getTarget().getName() = ["SignData", "SignPreHash"] and
    algo = "slh-dsa-sign"
  )
  or
  // Instance: verification
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "SlhDsa" and
    mc.getTarget().getName() = ["VerifyData", "VerifyPreHash"] and
    algo = "slh-dsa-verify"
  )
  or
  // Instance: key export
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "SlhDsa" and
    mc.getTarget().getName() = [
      "ExportSlhDsaPublicKey", "ExportSlhDsaPrivateKey",
      "TryExportSlhDsaPublicKey", "TryExportSlhDsaPrivateKey",
      "ExportSubjectPublicKeyInfo", "ExportPkcs8PrivateKey",
      "TryExportSubjectPublicKeyInfo", "TryExportPkcs8PrivateKey",
      "ExportSubjectPublicKeyInfoPem", "ExportPkcs8PrivateKeyPem",
      "ExportEncryptedPkcs8PrivateKey", "ExportEncryptedPkcs8PrivateKeyPem",
      "TryExportEncryptedPkcs8PrivateKey"
    ] and
    algo = "slh-dsa-key-export"
  )
  or
  // SlhDsaAlgorithm static property reads — all 12 FIPS 205 parameter sets
  exists(PropertyAccess pa |
    pa instanceof AssignableRead and
    pa = call and
    pa.getTarget().getDeclaringType().getName() = "SlhDsaAlgorithm"
  |
    pa.getTarget().getName() = "SlhDsaSha2_128s"  and algo = "slh-dsa-sha2-128s"  or
    pa.getTarget().getName() = "SlhDsaSha2_128f"  and algo = "slh-dsa-sha2-128f"  or
    pa.getTarget().getName() = "SlhDsaSha2_192s"  and algo = "slh-dsa-sha2-192s"  or
    pa.getTarget().getName() = "SlhDsaSha2_192f"  and algo = "slh-dsa-sha2-192f"  or
    pa.getTarget().getName() = "SlhDsaSha2_256s"  and algo = "slh-dsa-sha2-256s"  or
    pa.getTarget().getName() = "SlhDsaSha2_256f"  and algo = "slh-dsa-sha2-256f"  or
    pa.getTarget().getName() = "SlhDsaShake128s"  and algo = "slh-dsa-shake-128s" or
    pa.getTarget().getName() = "SlhDsaShake128f"  and algo = "slh-dsa-shake-128f" or
    pa.getTarget().getName() = "SlhDsaShake192s"  and algo = "slh-dsa-shake-192s" or
    pa.getTarget().getName() = "SlhDsaShake192f"  and algo = "slh-dsa-shake-192f" or
    pa.getTarget().getName() = "SlhDsaShake256s"  and algo = "slh-dsa-shake-256s" or
    pa.getTarget().getName() = "SlhDsaShake256f"  and algo = "slh-dsa-shake-256f"
  )
}

// ---------------------------------------------------------------------------
// Composite ML-DSA — ML-DSA combined with a classical algorithm (experimental)
// ---------------------------------------------------------------------------
private predicate isCompositeMlDsaDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = "CompositeMLDsa"
  |
    mc.getTarget().getName() = "GenerateKey" and
      algo = "composite-ml-dsa-keygen"
    or
    mc.getTarget().getName() = [
      "ImportSubjectPublicKeyInfo", "ImportPkcs8PrivateKey", "ImportFromPem",
      "ImportEncryptedPkcs8PrivateKey", "ImportFromEncryptedPem",
      "ImportCompositeMLDsaPrivateKey", "ImportCompositeMLDsaPublicKey"
    ] and
      algo = "composite-ml-dsa"
    or
    mc.getTarget().getName() = ["SignData", "SignPreHash"] and
      algo = "composite-ml-dsa-sign"
    or
    mc.getTarget().getName() = ["VerifyData", "VerifyPreHash"] and
      algo = "composite-ml-dsa-verify"
    or
    mc.getTarget().getName() = [
      "ExportCompositeMLDsaPrivateKey", "ExportCompositeMLDsaPublicKey",
      "TryExportCompositeMLDsaPrivateKey", "TryExportCompositeMLDsaPublicKey",
      "ExportSubjectPublicKeyInfo", "ExportPkcs8PrivateKey",
      "ExportSubjectPublicKeyInfoPem", "ExportPkcs8PrivateKeyPem",
      "ExportEncryptedPkcs8PrivateKey", "ExportEncryptedPkcs8PrivateKeyPem",
      "TryExportEncryptedPkcs8PrivateKey"
    ] and
      algo = "composite-ml-dsa-key-export"
  )
  or
  // CompositeMLDsaAlgorithm property reads — the property name is the parameter set,
  // e.g. MLDsa65WithECDsaP384, so it is emitted verbatim rather than enumerated.
  exists(PropertyAccess pa |
    pa instanceof AssignableRead and
    pa = call and
    pa.getTarget().getDeclaringType().getName() = "CompositeMLDsaAlgorithm" and
    algo = "composite-" + pa.getTarget().getName().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// SP 800-108 HMAC Counter-mode KDF (NIST SP 800-108)
// ---------------------------------------------------------------------------
private predicate isSp800108KdfDetection(Expr call, string algo) {
  // Constructor: new SP800108HmacCounterKdf(key, HashAlgorithmName)
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "SP800108HmacCounterKdf"
  |
    exists(string h | hashAlgoNameArg(oc.getArgument(1), h) and algo = h)
    or
    not exists(string h | hashAlgoNameArg(oc.getArgument(1), h)) and
      algo = "sp800-108-hmac-kdf"
  )
  or
  // Static one-shot: DeriveBytes(key, HashAlgorithmName, label, context, length) — resolve the hash
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getDeclaringType().getName() = "SP800108HmacCounterKdf" and
    mc.getTarget().getName() = "DeriveBytes"
  |
    exists(string h | hashAlgoNameArg(mc.getArgument(1), h) and algo = h)
    or
    not exists(string h | hashAlgoNameArg(mc.getArgument(1), h)) and
      algo = "sp800-108-hmac-derive"
  )
  or
  // Instance: DeriveKey — algorithm was fixed at construction time
  exists(MethodCall mc |
    mc = call and
    not mc.getTarget().isStatic() and
    mc.getTarget().getDeclaringType().getName() = "SP800108HmacCounterKdf" and
    mc.getTarget().getName() = "DeriveKey" and
    algo = "sp800-108-hmac-derive"
  )
}

// =============================================================================
// Select
// =============================================================================

from Expr call, string algo, string api
where
  api = "Microsoft.Bcl.Cryptography" and
  not call.getFile().getBaseName() = ["_cbom_type_stubs.cs", "type-stubs.cs"] and
  (
    isMlDsaDetection(call, algo)          or
    isMlKemDetection(call, algo)          or
    isSlhDsaDetection(call, algo)         or
    isCompositeMlDsaDetection(call, algo) or
    isSp800108KdfDetection(call, algo)
  )
select call, "algo=" + algo + ", api=" + api
