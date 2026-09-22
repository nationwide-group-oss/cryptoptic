/**
 * @name Crypto inventory — System.Security.Cryptography.Cng / NCrypt (C#/.NET)
 * @description Inventory of Windows CNG (Cryptography Next Generation) usage via
 *              System.Security.Cryptography.Cng: CngKey lifecycle (Create, Open, Import,
 *              Export, Delete), CNG-backed algorithm instances (RSACng, ECDsaCng,
 *              ECDiffieHellmanCng, AesCng, TripleDESCng), and CngAlgorithm / CngProvider
 *              configuration properties.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/csharp-cbom-ncrypt
 * @tags security
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow

/**
 * Holds if `t` is declared in System.Security.Cryptography or any sub-namespace.
 * CNG types (CngKey, RSACng, AesCng, etc.) live here and ARE resolvable from
 * .NET reference assemblies, so the namespace guard is reliable.
 */
predicate inCngNamespace(ValueOrRefType t) {
  t.getNamespace().getFullName().matches("System.Security.Cryptography%")
}

// =============================================================================
// CngAlgorithm — static property resolution with local data flow
// =============================================================================

/**
 * Direct: `CngAlgorithm.Rsa`, `CngAlgorithm.ECDsaP256`, etc.
 * Only key algorithms are listed: a CngKey cannot be a hash, so hash identifiers
 * are reported by `isCngAlgorithmPropertyDetection` instead.
 * Note: `CngAlgorithm` has no `Aes`, `TripleDes`, or `Dh` static properties in any
 * .NET version (verified against dotnet/runtime and .NET Framework reference source) —
 * those algorithms are only reachable via `new CngAlgorithm("AES")` etc., handled by
 * `isCngAlgorithmStringDetection`. `MLDsa`/`MLKem`/`SlhDsa`/`CompositeMLDsa`/
 * `CompositeMLKem` are real .NET 10+ additions.
 */
private predicate cngAlgoDirect(Expr arg, string algo) {
  arg.(PropertyAccess).getTarget().getDeclaringType().getName() = "CngAlgorithm" and
  inCngNamespace(arg.(PropertyAccess).getTarget().getDeclaringType()) and
  (
    arg.(PropertyAccess).getTarget().getName() = "Rsa"                 and algo = "rsa-keygen"        or
    arg.(PropertyAccess).getTarget().getName() = "ECDsa"               and algo = "ecdsa-keygen"      or
    arg.(PropertyAccess).getTarget().getName() = "ECDsaP256"           and algo = "ecdsa-p256-keygen" or
    arg.(PropertyAccess).getTarget().getName() = "ECDsaP384"           and algo = "ecdsa-p384-keygen" or
    arg.(PropertyAccess).getTarget().getName() = "ECDsaP521"           and algo = "ecdsa-p521-keygen" or
    arg.(PropertyAccess).getTarget().getName() = "ECDiffieHellman"     and algo = "ecdh-keygen"       or
    arg.(PropertyAccess).getTarget().getName() = "ECDiffieHellmanP256" and algo = "ecdh-p256-keygen"  or
    arg.(PropertyAccess).getTarget().getName() = "ECDiffieHellmanP384" and algo = "ecdh-p384-keygen"  or
    arg.(PropertyAccess).getTarget().getName() = "ECDiffieHellmanP521" and algo = "ecdh-p521-keygen"  or
    arg.(PropertyAccess).getTarget().getName() = "MLDsa"               and algo = "ml-dsa-keygen"     or
    arg.(PropertyAccess).getTarget().getName() = "MLKem"               and algo = "ml-kem-keygen"     or
    arg.(PropertyAccess).getTarget().getName() = "SlhDsa"              and algo = "slh-dsa-keygen"    or
    arg.(PropertyAccess).getTarget().getName() = "CompositeMLDsa"      and algo = "composite-ml-dsa-keygen" or
    arg.(PropertyAccess).getTarget().getName() = "CompositeMLKem"      and algo = "composite-ml-kem-keygen"
  )
}

/** Resolves a `CngAlgorithm` value, following local data flow through variables. */
predicate cngAlgoArg(Expr arg, string algo) {
  cngAlgoDirect(arg, algo)
  or
  exists(Expr src |
    src != arg and
    cngAlgoDirect(src, algo) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

// =============================================================================
// Detection predicates
// =============================================================================

// ---------------------------------------------------------------------------
// CngKey lifecycle (static factory methods + instance Export/Delete)
// ---------------------------------------------------------------------------
predicate isCngKeyCreateDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Create" and
    mc.getTarget().getDeclaringType().getName() = "CngKey" and
    inCngNamespace(mc.getTarget().getDeclaringType())
  |
    exists(string a | cngAlgoArg(mc.getArgument(0), a) and algo = a)
    or
    not exists(string a | cngAlgoArg(mc.getArgument(0), a)) and algo = "cng-key-create"
  )
}

predicate isCngKeyOpenDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Open" and
    mc.getTarget().getDeclaringType().getName() = "CngKey" and
    inCngNamespace(mc.getTarget().getDeclaringType()) and
    algo = "cng-key-open"
  )
}

predicate isCngKeyImportDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Import" and
    mc.getTarget().getDeclaringType().getName() = "CngKey" and
    inCngNamespace(mc.getTarget().getDeclaringType()) and
    algo = "cng-key-import"
  )
}

predicate isCngKeyExportDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    not mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Export" and
    mc.getTarget().getDeclaringType().getName() = "CngKey" and
    inCngNamespace(mc.getTarget().getDeclaringType()) and
    algo = "cng-key-export"
  )
}

predicate isCngKeyDeleteDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "Delete" and
    mc.getTarget().getDeclaringType().getName() = "CngKey" and
    inCngNamespace(mc.getTarget().getDeclaringType()) and
    algo = "cng-key-delete"
  )
}

// ---------------------------------------------------------------------------
// CNG-backed algorithm type constructors
// RSACng, ECDsaCng, ECDiffieHellmanCng — Windows CNG implementations of BCL
// abstract algorithm classes. AesCng / TripleDESCng are Windows-only symmetric.
// ---------------------------------------------------------------------------
predicate isCngAlgorithmTypeDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    inCngNamespace(oc.getTarget().getDeclaringType())
  |
    oc.getTarget().getDeclaringType().getName() = "RSACng"             and algo = "rsa-keygen"   or
    oc.getTarget().getDeclaringType().getName() = "ECDsaCng"           and algo = "ecdsa-keygen" or
    oc.getTarget().getDeclaringType().getName() = "ECDiffieHellmanCng" and algo = "ecdh-keygen"  or
    oc.getTarget().getDeclaringType().getName() = "AesCng"             and algo = "aes"          or
    oc.getTarget().getDeclaringType().getName() = "TripleDESCng"       and algo = "3des"
  )
}

// ---------------------------------------------------------------------------
// CngAlgorithm static property reads
// Identifies which algorithm identifiers the code references, covering usages
// not reachable via CngKey.Create() data flow (e.g. passed across method calls).
// ---------------------------------------------------------------------------
predicate isCngAlgorithmPropertyDetection(Expr call, string algo) {
  exists(PropertyAccess pa |
    pa = call and
    pa instanceof AssignableRead and
    pa.getTarget().getDeclaringType().getName() = "CngAlgorithm" and
    inCngNamespace(pa.getTarget().getDeclaringType())
  |
    pa.getTarget().getName() = "Rsa"                 and algo = "cng-algo-rsa"        or
    pa.getTarget().getName() = "ECDsa"               and algo = "cng-algo-ecdsa"      or
    pa.getTarget().getName() = "ECDsaP256"           and algo = "cng-algo-ecdsa-p256" or
    pa.getTarget().getName() = "ECDsaP384"           and algo = "cng-algo-ecdsa-p384" or
    pa.getTarget().getName() = "ECDsaP521"           and algo = "cng-algo-ecdsa-p521" or
    pa.getTarget().getName() = "ECDiffieHellman"     and algo = "cng-algo-ecdh"       or
    pa.getTarget().getName() = "ECDiffieHellmanP256" and algo = "cng-algo-ecdh-p256"  or
    pa.getTarget().getName() = "ECDiffieHellmanP384" and algo = "cng-algo-ecdh-p384"  or
    pa.getTarget().getName() = "ECDiffieHellmanP521" and algo = "cng-algo-ecdh-p521"  or
    pa.getTarget().getName() = "MD5"                 and algo = "cng-algo-md5"        or
    pa.getTarget().getName() = "Sha1"                and algo = "cng-algo-sha1"       or
    pa.getTarget().getName() = "Sha256"              and algo = "cng-algo-sha256"     or
    pa.getTarget().getName() = "Sha384"              and algo = "cng-algo-sha384"     or
    pa.getTarget().getName() = "Sha512"              and algo = "cng-algo-sha512"     or
    pa.getTarget().getName() = "MLDsa"               and algo = "cng-algo-ml-dsa"     or
    pa.getTarget().getName() = "MLKem"               and algo = "cng-algo-ml-kem"     or
    pa.getTarget().getName() = "SlhDsa"              and algo = "cng-algo-slh-dsa"    or
    pa.getTarget().getName() = "CompositeMLDsa"      and algo = "cng-algo-composite-ml-dsa" or
    pa.getTarget().getName() = "CompositeMLKem"      and algo = "cng-algo-composite-ml-kem"
  )
}

// ---------------------------------------------------------------------------
// CngProvider static property reads
// Identifies which Key Storage Provider (KSP) the code targets:
//   MicrosoftSoftwareKeyStorageProvider — software-only KSP
//   MicrosoftSmartCardKeyStorageProvider — smart card / HSM via PC/SC
//   MicrosoftPlatformCryptoProvider — TPM-backed hardware key storage
// ---------------------------------------------------------------------------
predicate isCngProviderPropertyDetection(Expr call, string algo) {
  exists(PropertyAccess pa |
    pa = call and
    pa instanceof AssignableRead and
    pa.getTarget().getDeclaringType().getName() = "CngProvider" and
    inCngNamespace(pa.getTarget().getDeclaringType())
  |
    pa.getTarget().getName() = "MicrosoftSoftwareKeyStorageProvider"  and algo = "cng-provider-software"  or
    pa.getTarget().getName() = "MicrosoftSmartCardKeyStorageProvider" and algo = "cng-provider-smartcard" or
    pa.getTarget().getName() = "MicrosoftPlatformCryptoProvider"      and algo = "cng-provider-tpm"
  )
}

// ---------------------------------------------------------------------------
// CngAlgorithm / CngKeyBlobFormat constructed from a provider algorithm string
// e.g. new CngAlgorithm("ECDSA_P256") — no static property exists for every
// CNG algorithm identifier, so the string form is common.
// ---------------------------------------------------------------------------
predicate isCngAlgorithmStringDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "CngAlgorithm" and
    inCngNamespace(oc.getTarget().getDeclaringType()) and
    algo = "cng-algo:" + oc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "CngProvider" and
    inCngNamespace(oc.getTarget().getDeclaringType()) and
    algo = "cng-provider:" + oc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "CngKeyBlobFormat" and
    inCngNamespace(oc.getTarget().getDeclaringType()) and
    algo = "cng-blob:" + oc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// CNG key length configured through CngKeyCreationParameters / CngProperty
// `new CngProperty("Length", BitConverter.GetBytes(2048), ...)` is the standard
// way of requesting a key size when creating a persisted CNG key.
// ---------------------------------------------------------------------------
predicate isCngKeyLengthDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "CngProperty" and
    inCngNamespace(oc.getTarget().getDeclaringType()) and
    algo = "cng-property:" + oc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "CngKeyCreationParameters" and
    inCngNamespace(oc.getTarget().getDeclaringType()) and
    algo = "cng-key-params"
  )
}

// ---------------------------------------------------------------------------
// Raw NCrypt / BCrypt P/Invoke interop
// Code that skips the managed CNG wrappers and calls ncrypt.dll / bcrypt.dll
// directly is invisible to every other detection in this query.
// ---------------------------------------------------------------------------

/** Holds if `mc` calls an `NCrypt*` / `BCrypt*` native entry point. */
private predicate cngInteropCall(MethodCall mc, string fn) {
  fn = mc.getTarget().getName() and
  (fn.matches("NCrypt%") or fn.matches("BCrypt%")) and
  not inCngNamespace(mc.getTarget().getDeclaringType())
}

/** Holds if the `fn` native entry point names a CNG algorithm in its string argument at `index`. */
private predicate cngInteropAlgoArg(string fn, int index) {
  fn = ["BCryptOpenAlgorithmProvider", "NCryptOpenStorageProvider"] and index = 1
  or
  fn = ["NCryptCreatePersistedKey", "NCryptSignHash", "NCryptVerifySignature"] and index = 2
}

predicate isCngInteropDetection(Expr call, string algo) {
  exists(MethodCall mc, string fn, int index |
    mc = call and
    cngInteropCall(mc, fn) and
    cngInteropAlgoArg(fn, index) and
    algo = "cng-algo:" + mc.getArgument(index).(StringLiteral).getValue().toLowerCase()
  )

  or

  exists(MethodCall mc, string fn |
    mc = call and
    cngInteropCall(mc, fn) and
    not exists(int index |
      cngInteropAlgoArg(fn, index) and
      exists(mc.getArgument(index).(StringLiteral))
    ) and
    algo = "cng-interop:" + fn.toLowerCase()
  )
}

// =============================================================================
// Select
// =============================================================================

from Expr call, string algo, string api
where
  api = "System.Security.Cryptography.Cng" and
  not call.getFile().getBaseName() = ["_cbom_type_stubs.cs", "type-stubs.cs"] and
  (
    isCngKeyCreateDetection(call, algo)     or
    isCngKeyOpenDetection(call, algo)       or
    isCngKeyImportDetection(call, algo)     or
    isCngKeyExportDetection(call, algo)     or
    isCngKeyDeleteDetection(call, algo)     or
    isCngAlgorithmTypeDetection(call, algo) or
    isCngAlgorithmPropertyDetection(call, algo) or
    isCngProviderPropertyDetection(call, algo) or
    isCngAlgorithmStringDetection(call, algo) or
    isCngKeyLengthDetection(call, algo) or
    isCngInteropDetection(call, algo)
  )
select call, "algo=" + algo + ", api=" + api
