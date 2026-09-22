/**
 * @name Crypto inventory — System.Security.Cryptography (C#/.NET)
 * @description Inventory of System.Security.Cryptography usage including hashes,
 *              HMAC, symmetric encryption, asymmetric primitives (RSA, ECDSA, ECDH,
 *              DSA), key derivation, CSPRNG, X.509/PKI, DPAPI, and miscellaneous
 *              cryptographic operations.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/csharp-cbom-system-security-cryptography
 * @tags security
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow

// =============================================================================
// Namespace helper
// =============================================================================

/**
 * Holds if `t` is declared in System.Security.Cryptography or any of its
 * sub-namespaces (e.g. System.Security.Cryptography.X509Certificates).
 */
predicate inSscNamespace(ValueOrRefType t) {
  t.getNamespace().getFullName().matches("System.Security.Cryptography%")
}

// =============================================================================
// Argument-value extraction helpers
// =============================================================================

/** Direct (literal) HashAlgorithmName resolution — no data flow. */
private predicate hashAlgoArgDirect(Expr arg, string name) {
  arg.(PropertyAccess).getTarget().getDeclaringType().getName() = "HashAlgorithmName" and
  name = arg.(PropertyAccess).getTarget().getName().toLowerCase()
  or
  arg.(FieldAccess).getTarget().getDeclaringType().getName() = "HashAlgorithmName" and
  name = arg.(FieldAccess).getTarget().getName().toLowerCase()
  or
  arg.(ObjectCreation).getTarget().getDeclaringType().getName() = "HashAlgorithmName" and
  name = arg.(ObjectCreation).getArgument(0).(StringLiteral).getValue().toLowerCase()
}

/**
 * Holds if `arg` is a HashAlgorithmName value whose canonical name is `name`
 * (lower-cased). Also resolves values stored in local variables (e.g. foreach).
 */
predicate hashAlgoArg(Expr arg, string name) {
  hashAlgoArgDirect(arg, name)
  or
  exists(Expr src |
    src != arg and
    hashAlgoArgDirect(src, name) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

/** Direct (literal) RSAEncryptionPadding resolution — no data flow. */
private predicate rsaEncPaddingArgDirect(Expr arg, string name) {
  arg.(PropertyAccess).getTarget().getDeclaringType().getName() = "RSAEncryptionPadding" and
  name = arg.(PropertyAccess).getTarget().getName()
  or
  arg.(FieldAccess).getTarget().getDeclaringType().getName() = "RSAEncryptionPadding" and
  name = arg.(FieldAccess).getTarget().getName()
}

/**
 * Holds if `arg` is an RSAEncryptionPadding value and `name` is the padding property
 * name (e.g. "OaepSHA256", "Pkcs1").
 */
predicate rsaEncPaddingArg(Expr arg, string name) {
  rsaEncPaddingArgDirect(arg, name)
  or
  exists(Expr src |
    src != arg and
    rsaEncPaddingArgDirect(src, name) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

/** Direct (literal) RSASignaturePadding resolution — no data flow. */
private predicate rsaSigPaddingArgDirect(Expr arg, string name) {
  arg.(PropertyAccess).getTarget().getDeclaringType().getName() = "RSASignaturePadding" and
  name = arg.(PropertyAccess).getTarget().getName()
  or
  arg.(FieldAccess).getTarget().getDeclaringType().getName() = "RSASignaturePadding" and
  name = arg.(FieldAccess).getTarget().getName()
}

/**
 * Holds if `arg` is an RSASignaturePadding value and `name` is the padding property
 * name (e.g. "Pkcs1", "Pss").
 */
predicate rsaSigPaddingArg(Expr arg, string name) {
  rsaSigPaddingArgDirect(arg, name)
  or
  exists(Expr src |
    src != arg and
    rsaSigPaddingArgDirect(src, name) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

/** Direct (literal) ECCurve resolution — no data flow. */
private predicate ecCurveArgDirect(Expr arg, string name) {
  // ECCurve.NamedCurves.nistP256 — the NamedCurves nested class
  arg.(PropertyAccess).getTarget().getDeclaringType().getName() = "NamedCurves" and
  name = arg.(PropertyAccess).getTarget().getName()
  or
  // Directly on ECCurve (some overloads)
  arg.(PropertyAccess).getTarget().getDeclaringType().getName() = "ECCurve" and
  name = arg.(PropertyAccess).getTarget().getName()
  or
  // ECCurve.CreateFromFriendlyName("secp256r1") — normalised to the NamedCurves spelling
  exists(string s |
    arg.(MethodCall).getTarget().getName() = "CreateFromFriendlyName" and
    arg.(MethodCall).getTarget().getDeclaringType().getName() = "ECCurve" and
    s = arg.(MethodCall).getArgument(0).(StringLiteral).getValue().toLowerCase()
  |
    s = ["nistp256", "secp256r1", "prime256v1"] and name = "nistP256" or
    s = ["nistp384", "secp384r1"]               and name = "nistP384" or
    s = ["nistp521", "secp521r1"]               and name = "nistP521" or
    s = "secp256k1"                             and name = "secP256k1" or
    s = "brainpoolp256r1"                       and name = "brainpoolP256r1" or
    s = "brainpoolp384r1"                       and name = "brainpoolP384r1" or
    s = "brainpoolp512r1"                       and name = "brainpoolP512r1"
  )
  or
  // ECCurve.CreateFromValue("1.2.840.10045.3.1.7") — curve OID
  exists(string oid |
    arg.(MethodCall).getTarget().getName() = "CreateFromValue" and
    arg.(MethodCall).getTarget().getDeclaringType().getName() = "ECCurve" and
    oid = arg.(MethodCall).getArgument(0).(StringLiteral).getValue()
  |
    oid = "1.2.840.10045.3.1.7" and name = "nistP256" or
    oid = "1.3.132.0.34"        and name = "nistP384" or
    oid = "1.3.132.0.35"        and name = "nistP521" or
    oid = "1.3.132.0.10"        and name = "secP256k1"
  )
}

/**
 * Holds if `arg` is a named ECCurve and `name` is the curve property name
 * (e.g. "nistP256", "brainpoolP384r1"). Also resolves values stored in local
 * variables (e.g. foreach loop iteration variables).
 */
predicate ecCurveArg(Expr arg, string name) {
  ecCurveArgDirect(arg, name)
  or
  exists(Expr src |
    src != arg and
    ecCurveArgDirect(src, name) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

/** Maps a PQC container type name (MLDsa/MLKem/SlhDsa) to its canonical dashed label. */
private predicate pqcTypeLabel(string typeName, string label) {
  typeName = "MLDsa"  and label = "ml-dsa"  or
  typeName = "MLKem"  and label = "ml-kem"  or
  typeName = "SlhDsa" and label = "slh-dsa"
}

/** Direct (literal) MLDsaAlgorithm/MLKemAlgorithm/SlhDsaAlgorithm resolution — no data flow. */
private predicate pqcAlgoArgDirect(Expr arg, string name) {
  exists(PropertyAccess pa, string declType, string propName |
    pa = arg and
    declType = pa.getTarget().getDeclaringType().getName() and
    declType = ["MLDsaAlgorithm", "MLKemAlgorithm", "SlhDsaAlgorithm"] and
    propName = pa.getTarget().getName()
  |
    propName = "MLDsa44"          and name = "ml-dsa-44"          or
    propName = "MLDsa65"          and name = "ml-dsa-65"          or
    propName = "MLDsa87"          and name = "ml-dsa-87"          or
    propName = "MLKem512"         and name = "ml-kem-512"         or
    propName = "MLKem768"         and name = "ml-kem-768"         or
    propName = "MLKem1024"        and name = "ml-kem-1024"        or
    propName = "SlhDsaSha2_128s"  and name = "slh-dsa-sha2-128s"  or
    propName = "SlhDsaSha2_128f"  and name = "slh-dsa-sha2-128f"  or
    propName = "SlhDsaSha2_192s"  and name = "slh-dsa-sha2-192s"  or
    propName = "SlhDsaSha2_192f"  and name = "slh-dsa-sha2-192f"  or
    propName = "SlhDsaSha2_256s"  and name = "slh-dsa-sha2-256s"  or
    propName = "SlhDsaSha2_256f"  and name = "slh-dsa-sha2-256f"  or
    propName = "SlhDsaShake128s"  and name = "slh-dsa-shake-128s" or
    propName = "SlhDsaShake128f"  and name = "slh-dsa-shake-128f" or
    propName = "SlhDsaShake192s"  and name = "slh-dsa-shake-192s" or
    propName = "SlhDsaShake192f"  and name = "slh-dsa-shake-192f" or
    propName = "SlhDsaShake256s"  and name = "slh-dsa-shake-256s" or
    propName = "SlhDsaShake256f"  and name = "slh-dsa-shake-256f"
  )
}

/**
 * Holds if `arg` is a named PQC algorithm and `name` is its canonical dashed label
 * (e.g. "ml-dsa-65"). Also resolves values stored in local variables.
 */
predicate pqcAlgoArg(Expr arg, string name) {
  pqcAlgoArgDirect(arg, name)
  or
  exists(Expr src |
    src != arg and
    pqcAlgoArgDirect(src, name) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

/** Maps a PbeEncryptionAlgorithm enum member name to its canonical dashed label. */
private predicate pbeEncAlgoLabel(string enumName, string label) {
  enumName = "Unknown"             and label = "unknown"      or
  enumName = "Aes128Cbc"           and label = "aes-128-cbc"  or
  enumName = "Aes192Cbc"           and label = "aes-192-cbc"  or
  enumName = "Aes256Cbc"           and label = "aes-256-cbc"  or
  enumName = "TripleDes3KeyPkcs12" and label = "3des-pkcs12"
}

/** Direct (literal) PbeEncryptionAlgorithm resolution — no data flow. */
private predicate pbeAlgoArgDirect(Expr arg, string name) {
  exists(string enumName |
    (
      arg.(PropertyAccess).getTarget().getDeclaringType().getName() = "PbeEncryptionAlgorithm" and
      enumName = arg.(PropertyAccess).getTarget().getName()
      or
      arg.(FieldAccess).getTarget().getDeclaringType().getName() = "PbeEncryptionAlgorithm" and
      enumName = arg.(FieldAccess).getTarget().getName()
    ) and
    pbeEncAlgoLabel(enumName, name)
  )
}

/**
 * Holds if `arg` is a PbeEncryptionAlgorithm value and `name` is its canonical dashed
 * label (e.g. "aes-256-cbc"). Also resolves values stored in local variables.
 */
predicate pbeAlgoArg(Expr arg, string name) {
  pbeAlgoArgDirect(arg, name)
  or
  exists(Expr src |
    src != arg and
    pbeAlgoArgDirect(src, name) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

/**
 * Direct integer literal, used to recover key sizes. Looks through the implicit
 * conversion introduced by nullable `int?` targets.
 */
private predicate intSizeDirect(Expr arg, string size) {
  arg.getType() instanceof IntType and
  size = arg.(Literal).getValue()
  or
  intSizeDirect(arg.(CastExpr).getExpr(), size)
}

/**
 * Holds if `arg` is, or reads a local variable assigned, an integer literal with
 * value `size`. Unlike the algorithm-name helpers this deliberately avoids
 * `DataFlow::localFlow`: every integer literal in the program would be a source.
 */
predicate intSizeArg(Expr arg, string size) {
  intSizeDirect(arg, size)
  or
  exists(LocalScopeVariable v |
    arg = v.getAnAccess() and
    intSizeDirect(v.getAnAssignedValue(), size)
  )
}

/** Maps a System.Security.Cryptography algorithm type name to a canonical algo label. */
private predicate symmetricTypeName(string typeName, string cipher) {
  typeName = ["Aes", "AesManaged", "AesCryptoServiceProvider", "AesCng"] and cipher = "aes" or
  typeName = ["TripleDES", "TripleDESCryptoServiceProvider", "TripleDESCng"] and cipher = "3des" or
  typeName = ["DES", "DESCryptoServiceProvider"] and cipher = "des" or
  typeName = ["RC2", "RC2CryptoServiceProvider"] and cipher = "rc2" or
  typeName = ["Rijndael", "RijndaelManaged"] and cipher = "rijndael"
}

/**
 * Holds if `config` configures property `prop` of an object of type `target` to
 * `value`, covering both `x.Prop = v` and the `new T { Prop = v }` initializer form.
 */
private predicate propertyConfig(Expr config, ValueOrRefType target, string prop, Expr value) {
  exists(Assignment a |
    a = config and
    prop = a.getLeftOperand().(PropertyAccess).getTarget().getName() and
    target = a.getLeftOperand().(PropertyAccess).getQualifier().getType() and
    value = a.getRightOperand()
  )
  or
  exists(MemberInitializer mi, ObjectCreation oc |
    mi = config and
    oc = mi.getParent().getParent() and
    prop = mi.getLeftOperand().(PropertyAccess).getTarget().getName() and
    target = oc.getType() and
    value = mi.getRightOperand()
  )
}

// =============================================================================
// Detection predicates — one per algorithm category
// =============================================================================

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------
predicate isHashDetection(Expr call, string algo) {
  // --- Static Create() factory: SHA256.Create(), MD5.Create(), HashAlgorithm.Create("SHA256") ---
  // resolvedType covers both the declaring type (standard .NET 5+) and the TypeAccess qualifier
  // to handle inherited Create() calls in older .NET Framework / .NET Standard targets where
  // the declaring type resolves to HashAlgorithm rather than the specific algorithm class.
  exists(MethodCall mc, ValueOrRefType resolvedType |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Create" and
    inSscNamespace(resolvedType) and
    (
      resolvedType = mc.getTarget().getDeclaringType() or
      resolvedType = mc.getQualifier().(TypeAccess).getTarget()
    )
  |
    resolvedType.getName() = "SHA1"        and algo = "sha1"      or
    resolvedType.getName() = "SHA256"      and algo = "sha256"    or
    resolvedType.getName() = "SHA384"      and algo = "sha384"    or
    resolvedType.getName() = "SHA512"      and algo = "sha512"    or
    resolvedType.getName() = "SHA3_256"    and algo = "sha3-256"  or
    resolvedType.getName() = "SHA3_384"    and algo = "sha3-384"  or
    resolvedType.getName() = "SHA3_512"    and algo = "sha3-512"  or
    resolvedType.getName() = "MD5"         and algo = "md5"       or
    resolvedType.getName() = "RIPEMD160"   and algo = "ripemd160" or
    // Note: Shake128/Shake256 have no Create() factory — detected via constructor and HashData below
    // HashAlgorithm.Create("SHA256") — string-based factory (legacy)
    (
      resolvedType.getName() = "HashAlgorithm" and
      mc.getNumberOfArguments() = 1 and
      algo = mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )
    or
    // HashAlgorithm.Create() — parameterless legacy factory, defaults to SHA-1
    (
      resolvedType.getName() = "HashAlgorithm" and
      mc.getNumberOfArguments() = 0 and
      algo = "sha1"
    )
  )

  or

  // --- Static one-shot HashData(): SHA256.HashData(data) (.NET 5+) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = ["HashData", "HashDataAsync"] and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    mc.getTarget().getDeclaringType().getName() = "SHA1"     and algo = "sha1"     or
    mc.getTarget().getDeclaringType().getName() = "SHA256"   and algo = "sha256"   or
    mc.getTarget().getDeclaringType().getName() = "SHA384"   and algo = "sha384"   or
    mc.getTarget().getDeclaringType().getName() = "SHA512"   and algo = "sha512"   or
    mc.getTarget().getDeclaringType().getName() = "SHA3_256" and algo = "sha3-256" or
    mc.getTarget().getDeclaringType().getName() = "SHA3_384" and algo = "sha3-384" or
    mc.getTarget().getDeclaringType().getName() = "SHA3_512" and algo = "sha3-512" or
    mc.getTarget().getDeclaringType().getName() = "MD5"      and algo = "md5"      or
    // Shake128/Shake256 (.NET 8+) — class names are camel-cased, not SHAKE128/SHAKE256
    mc.getTarget().getDeclaringType().getName() = "Shake128" and algo = "shake-128" or
    mc.getTarget().getDeclaringType().getName() = "Shake256" and algo = "shake-256"
  )

  or

  // --- Legacy managed/CryptoServiceProvider constructors (deprecated in .NET 6) ---
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType())
  |
    oc.getTarget().getDeclaringType().getName() = "SHA1Managed"              and algo = "sha1"   or
    oc.getTarget().getDeclaringType().getName() = "SHA256Managed"            and algo = "sha256" or
    oc.getTarget().getDeclaringType().getName() = "SHA384Managed"            and algo = "sha384" or
    oc.getTarget().getDeclaringType().getName() = "SHA512Managed"            and algo = "sha512" or
    oc.getTarget().getDeclaringType().getName() = "SHA1CryptoServiceProvider"   and algo = "sha1"   or
    oc.getTarget().getDeclaringType().getName() = "SHA256CryptoServiceProvider" and algo = "sha256" or
    oc.getTarget().getDeclaringType().getName() = "SHA384CryptoServiceProvider" and algo = "sha384" or
    oc.getTarget().getDeclaringType().getName() = "SHA512CryptoServiceProvider" and algo = "sha512" or
    oc.getTarget().getDeclaringType().getName() = "MD5CryptoServiceProvider"    and algo = "md5"    or
    oc.getTarget().getDeclaringType().getName() = "RIPEMD160Managed"            and algo = "ripemd160"
  )

  or

  // --- new Shake128() / new Shake256() constructors (.NET 8+) ---
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType())
  |
    oc.getTarget().getDeclaringType().getName() = "Shake128" and algo = "shake-128" or
    oc.getTarget().getDeclaringType().getName() = "Shake256" and algo = "shake-256"
  )

  or

  // --- IncrementalHash.CreateHash(HashAlgorithmName) — incremental / streaming hashing ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "CreateHash" and
    mc.getTarget().getDeclaringType().getName() = "IncrementalHash" and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    exists(string hashName | hashAlgoArg(mc.getArgument(0), hashName) and algo = hashName)
    or
    not exists(string h | hashAlgoArg(mc.getArgument(0), h)) and algo = "hash"
  )
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------
predicate isHmacDetection(Expr call, string algo) {
  // --- Constructors: new HMACSHA256(key) etc. ---
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType())
  |
    oc.getTarget().getDeclaringType().getName() = "HMACMD5"       and algo = "hmac-md5"      or
    oc.getTarget().getDeclaringType().getName() = "HMACSHA1"      and algo = "hmac-sha1"     or
    oc.getTarget().getDeclaringType().getName() = "HMACSHA256"    and algo = "hmac-sha256"   or
    oc.getTarget().getDeclaringType().getName() = "HMACSHA384"    and algo = "hmac-sha384"   or
    oc.getTarget().getDeclaringType().getName() = "HMACSHA512"    and algo = "hmac-sha512"   or
    oc.getTarget().getDeclaringType().getName() = "HMACSHA3_256"  and algo = "hmac-sha3-256" or
    oc.getTarget().getDeclaringType().getName() = "HMACSHA3_384"  and algo = "hmac-sha3-384" or
    oc.getTarget().getDeclaringType().getName() = "HMACSHA3_512"  and algo = "hmac-sha3-512" or
    oc.getTarget().getDeclaringType().getName() = "HMACRIPEMD160" and algo = "hmac-ripemd160" or
    oc.getTarget().getDeclaringType().getName() = "MACTripleDES"  and algo = "3des-cbc-mac"
  )

  or

  // --- HMAC.Create("HMACSHA256") / KeyedHashAlgorithm.Create(...) string factories ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Create" and
    mc.getTarget().getDeclaringType().getName() = ["HMAC", "KeyedHashAlgorithm"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    mc.getNumberOfArguments() = 1 and
    algo = mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )

  or

  // --- Static one-shot: HMACSHA256.HashData(key, data) (.NET 7+) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "HashData" and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    mc.getTarget().getDeclaringType().getName() = "HMACMD5"      and algo = "hmac-md5"      or
    mc.getTarget().getDeclaringType().getName() = "HMACSHA1"     and algo = "hmac-sha1"     or
    mc.getTarget().getDeclaringType().getName() = "HMACSHA256"   and algo = "hmac-sha256"   or
    mc.getTarget().getDeclaringType().getName() = "HMACSHA384"   and algo = "hmac-sha384"   or
    mc.getTarget().getDeclaringType().getName() = "HMACSHA512"   and algo = "hmac-sha512"   or
    mc.getTarget().getDeclaringType().getName() = "HMACSHA3_256" and algo = "hmac-sha3-256" or
    mc.getTarget().getDeclaringType().getName() = "HMACSHA3_384" and algo = "hmac-sha3-384" or
    mc.getTarget().getDeclaringType().getName() = "HMACSHA3_512" and algo = "hmac-sha3-512"
  )

  or

  // --- IncrementalHash.CreateHMAC(HashAlgorithmName, key) — incremental / streaming HMAC ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "CreateHMAC" and
    mc.getTarget().getDeclaringType().getName() = "IncrementalHash" and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    exists(string hashName |
      hashAlgoArg(mc.getArgument(0), hashName) and algo = "hmac-" + hashName
    )
    or
    not exists(string h | hashAlgoArg(mc.getArgument(0), h)) and algo = "hmac"
  )
}

// ---------------------------------------------------------------------------
// Symmetric encryption
// ---------------------------------------------------------------------------
predicate isSymmetricDetection(Expr call, string algo) {
  // --- Static Create() factory ---
  // resolvedType covers both the declaring type and the TypeAccess qualifier to handle
  // inherited Create() in older .NET targets (e.g. Aes inheriting from SymmetricAlgorithm).
  exists(MethodCall mc, ValueOrRefType resolvedType |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Create" and
    inSscNamespace(resolvedType) and
    (
      resolvedType = mc.getTarget().getDeclaringType() or
      resolvedType = mc.getQualifier().(TypeAccess).getTarget()
    )
  |
    resolvedType.getName() = "Aes"       and algo = "aes"  or
    resolvedType.getName() = "TripleDES" and algo = "3des" or
    resolvedType.getName() = "DES"       and algo = "des"  or
    resolvedType.getName() = "RC2"       and algo = "rc2"  or
    resolvedType.getName() = "Rijndael"  and algo = "rijndael" or
    // SymmetricAlgorithm.Create("AES") string factory (legacy)
    (
      resolvedType.getName() = "SymmetricAlgorithm" and
      mc.getNumberOfArguments() = 1 and
      algo = mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )
  )

  or

  // --- Constructors ---
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType())
  |
    // Classic CSP/Managed providers (legacy)
    oc.getTarget().getDeclaringType().getName() = "AesCryptoServiceProvider"       and algo = "aes"              or
    oc.getTarget().getDeclaringType().getName() = "AesManaged"                     and algo = "aes"              or
    oc.getTarget().getDeclaringType().getName() = "TripleDESCryptoServiceProvider" and algo = "3des"             or
    oc.getTarget().getDeclaringType().getName() = "DESCryptoServiceProvider"       and algo = "des"              or
    oc.getTarget().getDeclaringType().getName() = "RC2CryptoServiceProvider"       and algo = "rc2"              or
    oc.getTarget().getDeclaringType().getName() = "RijndaelManaged"                and algo = "rijndael"         or
    // AEAD constructors (.NET 3.0+)
    oc.getTarget().getDeclaringType().getName() = "AesGcm"           and algo = "aes-gcm"          or
    oc.getTarget().getDeclaringType().getName() = "AesCcm"           and algo = "aes-ccm"          or
    // ChaCha20-Poly1305 (.NET 8+)
    oc.getTarget().getDeclaringType().getName() = "ChaCha20Poly1305" and algo = "chacha20-poly1305"
  )
}

// ---------------------------------------------------------------------------
// Symmetric encryption — .NET 6+ one-shot APIs and AEAD operations
// ---------------------------------------------------------------------------
predicate isSymmetricOneShotDetection(Expr call, string algo) {
  // --- aes.EncryptCbc(...) / DecryptEcb(...) / TryEncryptCfb(...) (.NET 6+) ---
  exists(MethodCall mc, string cipher, string mode |
    mc = call and
    inSscNamespace(mc.getQualifier().getType().(ValueOrRefType)) and
    symmetricTypeName(mc.getQualifier().getType().(ValueOrRefType).getName(), cipher) and
    (
      mc.getTarget().getName() = ["EncryptCbc", "DecryptCbc", "TryEncryptCbc", "TryDecryptCbc"] and mode = "cbc" or
      mc.getTarget().getName() = ["EncryptEcb", "DecryptEcb", "TryEncryptEcb", "TryDecryptEcb"] and mode = "ecb" or
      mc.getTarget().getName() = ["EncryptCfb", "DecryptCfb", "TryEncryptCfb", "TryDecryptCfb"] and mode = "cfb"
    ) and
    algo = cipher + "-" + mode
  )

  or

  // --- AEAD instance operations: AesGcm / AesCcm / ChaCha20Poly1305 ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["Encrypt", "Decrypt"] and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    mc.getTarget().getDeclaringType().getName() = "AesGcm"           and algo = "aes-gcm" or
    mc.getTarget().getDeclaringType().getName() = "AesCcm"           and algo = "aes-ccm" or
    mc.getTarget().getDeclaringType().getName() = "ChaCha20Poly1305" and algo = "chacha20-poly1305"
  )
}

// ---------------------------------------------------------------------------
// Explicit cipher-mode and padding configuration
// ---------------------------------------------------------------------------
predicate isCipherModeConfigDetection(Expr call, string algo) {
  exists(ValueOrRefType target, Expr value, string cipher, string mode |
    propertyConfig(call, target, "Mode", value) and
    symmetricTypeName(target.getName(), cipher) and
    value.(FieldAccess).getTarget().getDeclaringType().getName() = "CipherMode" and
    mode = value.(FieldAccess).getTarget().getName().toLowerCase() and
    algo = cipher + "-" + mode
  )

  or

  exists(ValueOrRefType target, Expr value, string cipher, string padding |
    propertyConfig(call, target, "Padding", value) and
    symmetricTypeName(target.getName(), cipher) and
    value.(FieldAccess).getTarget().getDeclaringType().getName() = "PaddingMode" and
    padding = value.(FieldAccess).getTarget().getName().toLowerCase() and
    algo = cipher + "-padding-" + padding
  )
}

// ---------------------------------------------------------------------------
// Explicit key sizes
// `RSA.Create(2048)` and `new RSACryptoServiceProvider(2048)` are handled in the
// RSA section; this covers the `KeySize` property form used by every algorithm.
// ---------------------------------------------------------------------------
predicate isKeySizeDetection(Expr call, string algo) {
  exists(ValueOrRefType target, Expr value, string prefix, string size |
    propertyConfig(call, target, "KeySize", value) and
    inSscNamespace(target) and
    intSizeArg(value, size) and
    algo = prefix + "-" + size
  |
    symmetricTypeName(target.getName(), prefix)
    or
    target.getName() = ["RSA", "RSACryptoServiceProvider", "RSACng", "RSAOpenSsl"] and prefix = "rsa"
    or
    target.getName() = ["DSA", "DSACryptoServiceProvider", "DSAOpenSsl", "DSACng"] and prefix = "dsa"
  )
}

// ---------------------------------------------------------------------------
// Symmetric encryption — CreateEncryptor / CreateDecryptor with mode tracking
// ---------------------------------------------------------------------------
predicate isSymmetricEncryptionDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["CreateEncryptor", "CreateDecryptor"] and
    inSscNamespace(mc.getQualifier().getType().(ValueOrRefType))
  |
    // Resolve the cipher mode from a Mode property assignment on the same local variable
    exists(LocalVariable v, AssignExpr modeAssign, string cipherType |
      mc.getQualifier() = v.getAnAccess() and
      modeAssign.getLeftOperand().(PropertyAccess).getQualifier() = v.getAnAccess() and
      modeAssign.getLeftOperand().(PropertyAccess).getTarget().getName() = "Mode" and
      cipherType = v.getType().(ValueOrRefType).getName()
    |
      exists(string modeName |
        modeName = modeAssign.getRightOperand().(FieldAccess).getTarget().getName()
      |
        modeName = "CBC" and cipherType = "Aes"       and algo = "aes-cbc"  or
        modeName = "CBC" and cipherType = "TripleDES" and algo = "3des-cbc" or
        modeName = "ECB" and cipherType = "Aes"       and algo = "aes-ecb"  or
        modeName = "ECB" and cipherType = "TripleDES" and algo = "3des-ecb" or
        modeName = "CFB" and cipherType = "Aes"       and algo = "aes-cfb"  or
        modeName = "OFB" and cipherType = "Aes"       and algo = "aes-ofb"
      )
    )
    or
    // Fallback: mode not resolvable via local variable pattern
    not exists(LocalVariable v, AssignExpr modeAssign |
      mc.getQualifier() = v.getAnAccess() and
      modeAssign.getLeftOperand().(PropertyAccess).getQualifier() = v.getAnAccess() and
      modeAssign.getLeftOperand().(PropertyAccess).getTarget().getName() = "Mode"
    ) and
    (
      mc.getQualifier().getType().(ValueOrRefType).getName() = "Aes"       and algo = "aes-encrypt"  or
      mc.getQualifier().getType().(ValueOrRefType).getName() = "TripleDES" and algo = "3des-encrypt" or
      mc.getQualifier().getType().(ValueOrRefType).getName() = "DES"       and algo = "des-encrypt"  or
      mc.getQualifier().getType().(ValueOrRefType).getName() = "RC2"       and algo = "rc2-encrypt"  or
      mc.getQualifier().getType().(ValueOrRefType).getName() = ["Rijndael", "RijndaelManaged"] and
        algo = "rijndael-encrypt"
    )
  )
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------
predicate isRsaDetection(Expr call, string algo) {
  // --- RSA.Create() / RSA.Create(keySize) key generation ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Create" and
    (
      mc.getTarget().getDeclaringType().getName() = "RSA" and
      inSscNamespace(mc.getTarget().getDeclaringType())
      or
      mc.getQualifier().(TypeAccess).getTarget().(ValueOrRefType).getName() = "RSA" and
      inSscNamespace(mc.getQualifier().(TypeAccess).getTarget().(ValueOrRefType))
    )
  |
    exists(string ks | intSizeArg(mc.getArgument(0), ks) and algo = "rsa-" + ks + "-keygen")
    or
    not exists(string ks | intSizeArg(mc.getArgument(0), ks)) and algo = "rsa-keygen"
  )

  or

  // --- new RSACryptoServiceProvider(keySize) / new RSAOpenSsl(keySize) constructors ---
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType()) and
    (
      oc.getTarget().getDeclaringType().getName() = "RSACryptoServiceProvider" or
      oc.getTarget().getDeclaringType().getName() = "RSAOpenSsl"
    )
  |
    exists(string ks | intSizeArg(oc.getArgument(0), ks) and algo = "rsa-" + ks + "-keygen")
    or
    not exists(string ks | intSizeArg(oc.getArgument(0), ks)) and algo = "rsa-keygen"
  )

  or

  // --- RSA.Encrypt / Decrypt with detectable padding ---
  exists(MethodCall mc, string paddingName |
    mc = call and
    mc.getTarget().getName() = ["Encrypt", "Decrypt"] and
    mc.getTarget().getDeclaringType().getName() = ["RSA", "RSACryptoServiceProvider", "RSAOpenSsl"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    rsaEncPaddingArg(mc.getArgument(1), paddingName)
  |
    paddingName = "OaepSHA1"   and algo = "rsa-oaep-sha1"   or
    paddingName = "OaepSHA256" and algo = "rsa-oaep-sha256" or
    paddingName = "OaepSHA384" and algo = "rsa-oaep-sha384" or
    paddingName = "OaepSHA512" and algo = "rsa-oaep-sha512" or
    paddingName = "Pkcs1"      and algo = "rsa-pkcs1v15"
  )

  or

  // --- RSA.Encrypt / Decrypt without resolvable padding (fallback) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["Encrypt", "Decrypt"] and
    mc.getTarget().getDeclaringType().getName() = ["RSA", "RSACryptoServiceProvider", "RSAOpenSsl"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    not exists(string p | rsaEncPaddingArg(mc.getArgument(1), p)) and
    algo = "rsa-encrypt"
  )

  or

  // --- RSA.TryEncrypt / TryDecrypt — span overloads (.NET 5+); padding is at argument index 2 ---
  exists(MethodCall mc, string paddingName |
    mc = call and
    mc.getTarget().getName() = ["TryEncrypt", "TryDecrypt"] and
    mc.getTarget().getDeclaringType().getName() = ["RSA", "RSACryptoServiceProvider", "RSAOpenSsl"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    rsaEncPaddingArg(mc.getArgument(2), paddingName)
  |
    paddingName = "OaepSHA1"   and algo = "rsa-oaep-sha1"   or
    paddingName = "OaepSHA256" and algo = "rsa-oaep-sha256" or
    paddingName = "OaepSHA384" and algo = "rsa-oaep-sha384" or
    paddingName = "OaepSHA512" and algo = "rsa-oaep-sha512" or
    paddingName = "Pkcs1"      and algo = "rsa-pkcs1v15"
  )

  or

  // --- RSA.TryEncrypt / TryDecrypt without resolvable padding (fallback) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["TryEncrypt", "TryDecrypt"] and
    mc.getTarget().getDeclaringType().getName() = ["RSA", "RSACryptoServiceProvider", "RSAOpenSsl"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    not exists(string p | rsaEncPaddingArg(mc.getArgument(2), p)) and
    algo = "rsa-encrypt"
  )

  or

  // --- RSA.SignData / VerifyData / SignHash / VerifyHash with hash + padding ---
  // Signature methods: SignData(data, hash, padding) — hash is arg N-2, padding is arg N-1
  // TryVerifyData / TryVerifyHash have no out param so their arg layout matches.
  exists(MethodCall mc, string hashName, string paddingName |
    mc = call and
    mc.getTarget().getName() =
      ["SignData", "VerifyData", "SignHash", "VerifyHash", "TryVerifyData", "TryVerifyHash"] and
    mc.getTarget().getDeclaringType().getName() = ["RSA", "RSACryptoServiceProvider", "RSAOpenSsl"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    hashAlgoArg(mc.getArgument(mc.getNumberOfArguments() - 2), hashName) and
    rsaSigPaddingArg(mc.getArgument(mc.getNumberOfArguments() - 1), paddingName)
  |
    paddingName = "Pkcs1" and algo = "rsa-pkcs1-sign-" + hashName or
    paddingName = "Pss"   and algo = "rsa-pss-sign-" + hashName
  )

  or

  // --- RSA.TrySignData / TrySignHash — span overloads with out param; hash at N-3, padding at N-2 ---
  exists(MethodCall mc, string hashName, string paddingName |
    mc = call and
    mc.getTarget().getName() = ["TrySignData", "TrySignHash"] and
    mc.getTarget().getDeclaringType().getName() = ["RSA", "RSACryptoServiceProvider", "RSAOpenSsl"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    hashAlgoArg(mc.getArgument(mc.getNumberOfArguments() - 3), hashName) and
    rsaSigPaddingArg(mc.getArgument(mc.getNumberOfArguments() - 2), paddingName)
  |
    paddingName = "Pkcs1" and algo = "rsa-pkcs1-sign-" + hashName or
    paddingName = "Pss"   and algo = "rsa-pss-sign-" + hashName
  )

  or

  // --- RSA sign/verify without fully resolvable parameters (fallback) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() =
      ["SignData", "VerifyData", "SignHash", "VerifyHash",
       "TrySignData", "TryVerifyData", "TrySignHash", "TryVerifyHash"] and
    mc.getTarget().getDeclaringType().getName() = ["RSA", "RSACryptoServiceProvider", "RSAOpenSsl"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    not (
      exists(string h | hashAlgoArg(mc.getArgument(mc.getNumberOfArguments() - 2), h)) and
      exists(string p | rsaSigPaddingArg(mc.getArgument(mc.getNumberOfArguments() - 1), p))
    ) and
    not (
      exists(string h | hashAlgoArg(mc.getArgument(mc.getNumberOfArguments() - 3), h)) and
      exists(string p | rsaSigPaddingArg(mc.getArgument(mc.getNumberOfArguments() - 2), p))
    ) and
    algo = "rsa-sign"
  )

  or

  // --- RSA key material export operations ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = [
      "ExportSubjectPublicKeyInfoPem", "ExportSubjectPublicKeyInfo",
      "ExportPkcs8PrivateKeyPem", "ExportPkcs8PrivateKey",
      "ExportRSAPublicKeyPem", "ExportRSAPublicKey",
      "ExportRSAPrivateKeyPem", "ExportRSAPrivateKey",
      "ExportEncryptedPkcs8PrivateKeyPem", "ExportEncryptedPkcs8PrivateKey"
    ] and
    mc.getQualifier().getType().(ValueOrRefType).getABaseType*().getName() = "RSA" and
    inSscNamespace(mc.getQualifier().getType().(ValueOrRefType)) and
    algo = "rsa-key-export"
  )

  or

  // --- RSA key material import operations ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = [
      "ImportSubjectPublicKeyInfo", "ImportPkcs8PrivateKey",
      "ImportRSAPublicKey", "ImportRSAPrivateKey",
      "ImportEncryptedPkcs8PrivateKey", "ImportFromPem", "ImportFromEncryptedPem",
      "ImportParameters"
    ] and
    mc.getQualifier().getType().(ValueOrRefType).getABaseType*().getName() = "RSA" and
    inSscNamespace(mc.getQualifier().getType().(ValueOrRefType)) and
    algo = "rsa-key-import"
  )
}

// ---------------------------------------------------------------------------
// ECDSA
// ---------------------------------------------------------------------------
predicate isEcdsaDetection(Expr call, string algo) {
  // --- ECDsa.Create() / ECDsa.Create(namedCurve) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Create" and
    (
      mc.getTarget().getDeclaringType().getName() = "ECDsa" and
      inSscNamespace(mc.getTarget().getDeclaringType())
      or
      mc.getQualifier().(TypeAccess).getTarget().(ValueOrRefType).getName() = "ECDsa" and
      inSscNamespace(mc.getQualifier().(TypeAccess).getTarget().(ValueOrRefType))
    )
  |
    mc.getNumberOfArguments() = 0 and algo = "ecdsa-keygen"
    or
    mc.getNumberOfArguments() = 1 and (
      ecCurveArg(mc.getArgument(0), "nistP256")       and algo = "ecdsa-p256-keygen"             or
      ecCurveArg(mc.getArgument(0), "nistP384")       and algo = "ecdsa-p384-keygen"             or
      ecCurveArg(mc.getArgument(0), "nistP521")       and algo = "ecdsa-p521-keygen"             or
      ecCurveArg(mc.getArgument(0), "secP256k1")      and algo = "ecdsa-secp256k1-keygen"        or
      ecCurveArg(mc.getArgument(0), "brainpoolP256r1") and algo = "ecdsa-brainpoolp256r1-keygen" or
      ecCurveArg(mc.getArgument(0), "brainpoolP384r1") and algo = "ecdsa-brainpoolp384r1-keygen" or
      ecCurveArg(mc.getArgument(0), "brainpoolP512r1") and algo = "ecdsa-brainpoolp512r1-keygen" or
      not exists(string c | ecCurveArg(mc.getArgument(0), c)) and algo = "ecdsa-keygen"
    )
  )

  or

  // --- new ECDsaCng() / new ECDsaOpenSsl() constructors ---
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType()) and
    (
      oc.getTarget().getDeclaringType().getName() = "ECDsaCng" or
      oc.getTarget().getDeclaringType().getName() = "ECDsaOpenSsl"
    ) and
    algo = "ecdsa-keygen"
  )

  or

  // --- ECDsa.SignData / VerifyData with detectable hash algorithm ---
  // Hash is the last argument (no padding param unlike RSA). TryVerifyData also has hash as last arg.
  exists(MethodCall mc, string hashName |
    mc = call and
    mc.getTarget().getName() =
      ["SignData", "VerifyData", "SignHash", "VerifyHash", "TryVerifyData"] and
    mc.getTarget().getDeclaringType().getName() = ["ECDsa", "ECDsaCng", "ECDsaOpenSsl"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    hashAlgoArg(mc.getArgument(mc.getNumberOfArguments() - 1), hashName) and
    algo = "ecdsa-sign-" + hashName
  )

  or

  // --- ECDsa.TrySignData — span overload; hash is at N-2 due to trailing out param ---
  exists(MethodCall mc, string hashName |
    mc = call and
    mc.getTarget().getName() = "TrySignData" and
    mc.getTarget().getDeclaringType().getName() = ["ECDsa", "ECDsaCng", "ECDsaOpenSsl"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    hashAlgoArg(mc.getArgument(mc.getNumberOfArguments() - 2), hashName) and
    algo = "ecdsa-sign-" + hashName
  )

  or

  // --- ECDsa sign/verify without resolvable hash (fallback) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() =
      ["SignData", "VerifyData", "SignHash", "VerifyHash",
       "TrySignData", "TryVerifyData", "TrySignHash", "TryVerifyHash"] and
    mc.getTarget().getDeclaringType().getName() = ["ECDsa", "ECDsaCng", "ECDsaOpenSsl"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    not exists(string h | hashAlgoArg(mc.getArgument(mc.getNumberOfArguments() - 1), h)) and
    not exists(string h | hashAlgoArg(mc.getArgument(mc.getNumberOfArguments() - 2), h)) and
    algo = "ecdsa-sign"
  )
}

// ---------------------------------------------------------------------------
// ECDH (EC Diffie-Hellman)
// ---------------------------------------------------------------------------
predicate isEcdhDetection(Expr call, string algo) {
  // --- ECDiffieHellman.Create() / ECDiffieHellman.Create(namedCurve) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Create" and
    (
      mc.getTarget().getDeclaringType().getName() = "ECDiffieHellman" and
      inSscNamespace(mc.getTarget().getDeclaringType())
      or
      mc.getQualifier().(TypeAccess).getTarget().(ValueOrRefType).getName() = "ECDiffieHellman" and
      inSscNamespace(mc.getQualifier().(TypeAccess).getTarget().(ValueOrRefType))
    )
  |
    mc.getNumberOfArguments() = 0 and algo = "ecdh-keygen"
    or
    mc.getNumberOfArguments() = 1 and (
      ecCurveArg(mc.getArgument(0), "nistP256")  and algo = "ecdh-p256-keygen" or
      ecCurveArg(mc.getArgument(0), "nistP384")  and algo = "ecdh-p384-keygen" or
      ecCurveArg(mc.getArgument(0), "nistP521")  and algo = "ecdh-p521-keygen" or
      ecCurveArg(mc.getArgument(0), "secP256k1") and algo = "ecdh-secp256k1-keygen" or
      not exists(string c | ecCurveArg(mc.getArgument(0), c)) and algo = "ecdh-keygen"
    )
  )

  or

  // --- new ECDiffieHellmanCng() / new ECDiffieHellmanOpenSsl() constructors ---
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType()) and
    (
      oc.getTarget().getDeclaringType().getName() = "ECDiffieHellmanCng" or
      oc.getTarget().getDeclaringType().getName() = "ECDiffieHellmanOpenSsl"
    ) and
    algo = "ecdh-keygen"
  )

  or

  // --- ECDH key derivation operations ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = [
      "DeriveKeyMaterial",
      "DeriveKeyFromHash",
      "DeriveKeyFromHmac",
      "DeriveKeyTls"
    ] and
    mc.getTarget().getDeclaringType().getName() =
      ["ECDiffieHellman", "ECDiffieHellmanCng", "ECDiffieHellmanOpenSsl"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = "ecdh-derive"
  )
}

// ---------------------------------------------------------------------------
// DSA
// ---------------------------------------------------------------------------
predicate isDsaDetection(Expr call, string algo) {
  // --- DSA.Create() factory ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Create" and
    (
      mc.getTarget().getDeclaringType().getName() = "DSA" and
      inSscNamespace(mc.getTarget().getDeclaringType())
      or
      mc.getQualifier().(TypeAccess).getTarget().(ValueOrRefType).getName() = "DSA" and
      inSscNamespace(mc.getQualifier().(TypeAccess).getTarget().(ValueOrRefType))
    )
  |
    exists(string ks | intSizeArg(mc.getArgument(0), ks) and algo = "dsa-" + ks + "-keygen")
    or
    not exists(string ks | intSizeArg(mc.getArgument(0), ks)) and algo = "dsa-keygen"
  )

  or

  // --- new DSACryptoServiceProvider() / new DSAOpenSsl() / new DSACng() constructors ---
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType()) and
    (
      oc.getTarget().getDeclaringType().getName() = "DSACryptoServiceProvider" or
      oc.getTarget().getDeclaringType().getName() = "DSAOpenSsl" or
      oc.getTarget().getDeclaringType().getName() = "DSACng"
    )
  |
    exists(string ks | intSizeArg(oc.getArgument(0), ks) and algo = "dsa-" + ks + "-keygen")
    or
    not exists(string ks | intSizeArg(oc.getArgument(0), ks)) and algo = "dsa-keygen"
  )

  or

  // --- DSA.SignData / VerifyData / CreateSignature / VerifySignature and span-based Try* overloads ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = [
      "SignData", "VerifyData", "CreateSignature", "VerifySignature",
      "TrySignData", "TryVerifyData", "TryCreateSignature"
    ] and
    mc.getTarget().getDeclaringType().getName() =
      ["DSA", "DSACryptoServiceProvider", "DSAOpenSsl", "DSACng"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = "dsa-sign"
  )
}

// ---------------------------------------------------------------------------
// Key Derivation Functions (KDF)
// ---------------------------------------------------------------------------
predicate isKdfDetection(Expr call, string algo) {
  // --- new Rfc2898DeriveBytes(password, salt, iterations[, hashAlgorithmName]) ---
  // Overloads with a HashAlgorithmName parameter were added in .NET 5.
  // Without it, the default is SHA-1.
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "Rfc2898DeriveBytes" and
    inSscNamespace(oc.getTarget().getDeclaringType())
  |
    exists(string hashName |
      hashAlgoArg(oc.getArgument(oc.getNumberOfArguments() - 1), hashName) and
      algo = "pbkdf2-" + hashName
    )
    or
    (
      not exists(string h | hashAlgoArg(oc.getArgument(oc.getNumberOfArguments() - 1), h)) and
      algo = "pbkdf2-sha1" // SHA-1 is the implicit default on older overloads
    )
  )

  or

  // --- Rfc2898DeriveBytes.Pbkdf2(...) static one-shot (.NET 6+) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Pbkdf2" and
    mc.getTarget().getDeclaringType().getName() = "Rfc2898DeriveBytes" and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    // hashAlgorithm is the 4th positional argument (index 3)
    exists(string hashName |
      hashAlgoArg(mc.getArgument(3), hashName) and
      algo = "pbkdf2-" + hashName
    )
    or
    not exists(string h | hashAlgoArg(mc.getArgument(3), h)) and algo = "pbkdf2"
  )

  or

  // --- new PasswordDeriveBytes (deprecated PBKDF1-style derivation) ---
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "PasswordDeriveBytes" and
    inSscNamespace(oc.getTarget().getDeclaringType()) and
    algo = "pbkdf1"
  )

  or

  // --- HKDF.DeriveKey / Extract / Expand (.NET 5+) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getDeclaringType().getName() = "HKDF" and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    mc.getTarget().getName() = "DeriveKey" and (
      exists(string hashName | hashAlgoArg(mc.getArgument(0), hashName) and algo = "hkdf-" + hashName)
      or
      not exists(string h | hashAlgoArg(mc.getArgument(0), h)) and algo = "hkdf"
    )
    or
    mc.getTarget().getName() = ["Extract", "Expand"] and algo = "hkdf"
  )

  or

  // --- new SP800108HmacCounterKdf(key, hashAlgorithm) — NIST SP 800-108 counter-mode KDF (.NET 8+) ---
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "SP800108HmacCounterKdf" and
    inSscNamespace(oc.getTarget().getDeclaringType())
  |
    exists(string hashName |
      hashAlgoArg(oc.getArgument(oc.getNumberOfArguments() - 1), hashName) and
      algo = "sp800-108-hmac-counter-" + hashName
    )
    or
    not exists(string h | hashAlgoArg(oc.getArgument(oc.getNumberOfArguments() - 1), h)) and
    algo = "sp800-108-hmac-counter"
  )

  or

  // --- SP800108HmacCounterKdf.DeriveBytes(...) / .DeriveKey(...) static one-shot ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = ["DeriveBytes", "DeriveKey"] and
    mc.getTarget().getDeclaringType().getName() = "SP800108HmacCounterKdf" and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    exists(string hashName |
      hashAlgoArg(mc.getArgument(1), hashName) and
      algo = "sp800-108-hmac-counter-" + hashName
    )
    or
    not exists(string h | hashAlgoArg(mc.getArgument(1), h)) and
    algo = "sp800-108-hmac-counter"
  )

  or

  // --- instance kdf.DeriveKey(label, context, length) on a constructed SP800108HmacCounterKdf ---
  exists(MethodCall mc |
    mc = call and
    not mc.getTarget().isStatic() and
    mc.getTarget().getName() = "DeriveKey" and
    mc.getTarget().getDeclaringType().getName() = "SP800108HmacCounterKdf" and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = "sp800-108-hmac-counter"
  )
}

// ---------------------------------------------------------------------------
// Cryptographically Secure Random Number Generation
// ---------------------------------------------------------------------------
predicate isRandomDetection(Expr call, string algo) {
  // --- RandomNumberGenerator static utility methods (.NET 6+) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getDeclaringType().getName() = "RandomNumberGenerator" and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    mc.getTarget().getName() =
      ["GetBytes", "GetNonZeroBytes", "GetInt32", "Fill", "GetHexString", "GetString"] and
    algo = "csprng"
  )

  or

  // --- RandomNumberGenerator.Create() — returns a configured instance ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Create" and
    (
      mc.getTarget().getDeclaringType().getName() = "RandomNumberGenerator" and
      inSscNamespace(mc.getTarget().getDeclaringType())
      or
      mc.getQualifier().(TypeAccess).getTarget().(ValueOrRefType).getName() = "RandomNumberGenerator" and
      inSscNamespace(mc.getQualifier().(TypeAccess).getTarget().(ValueOrRefType))
    ) and
    algo = "csprng"
  )

  or

  // --- new RNGCryptoServiceProvider() — deprecated in .NET 6 ---
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "RNGCryptoServiceProvider" and
    inSscNamespace(oc.getTarget().getDeclaringType()) and
    algo = "csprng"
  )
}

// ---------------------------------------------------------------------------
// X.509 / PKI
// ---------------------------------------------------------------------------
predicate isPkiDetection(Expr call, string algo) {
  // --- new X509Certificate2(...) / new X509Certificate(...) ---
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType()) and
    oc.getTarget().getDeclaringType().getName() = ["X509Certificate2", "X509Certificate"] and
    algo = "x509-certificate"
  )

  or

  // --- X509Certificate2 static factory methods: CreateFromPem, CreateFromCertFile ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = ["CreateFromPem", "CreateFromCertFile", "CreateFromSignedFile"] and
    mc.getTarget().getDeclaringType().getName() = ["X509Certificate2", "X509Certificate"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = "x509-certificate"
  )

  or

  // --- new CertificateRequest(subjectName, key, hashAlgorithm) — CSR creation ---
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "CertificateRequest" and
    inSscNamespace(oc.getTarget().getDeclaringType()) and
    algo = "x509-csr"
  )

  or

  // --- CertificateRequest.CreateSelfSigned(...) (.NET 5+) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "CreateSelfSigned" and
    mc.getTarget().getDeclaringType().getName() = "CertificateRequest" and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = "x509-self-signed"
  )

  or

  // --- new X509Store(...) — opens a certificate store ---
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "X509Store" and
    inSscNamespace(oc.getTarget().getDeclaringType()) and
    algo = "x509-store"
  )

  or

  // --- X509Chain.Build(certificate) — certificate chain validation ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "Build" and
    mc.getTarget().getDeclaringType().getName() = "X509Chain" and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = "x509-chain-verify"
  )

  or

  // --- Certificate export operations ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["ExportCertificatePem", "Export", "GetRawCertData",
                                  "GetRawCertDataString"] and
    mc.getTarget().getDeclaringType().getName() = ["X509Certificate2", "X509Certificate"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = "x509-export"
  )
}

// ---------------------------------------------------------------------------
// Data Protection API (DPAPI)
// ---------------------------------------------------------------------------
predicate isDpapiDetection(Expr call, string algo) {
  // --- ProtectedData.Protect / Unprotect (user/machine key scope) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getDeclaringType().getName() = "ProtectedData" and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    mc.getTarget().getName() = "Protect"   and algo = "dpapi-protect"   or
    mc.getTarget().getName() = "Unprotect" and algo = "dpapi-unprotect"
  )

  or

  // --- ProtectedMemory.Protect / Unprotect (in-process memory scope) ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getDeclaringType().getName() = "ProtectedMemory" and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    mc.getTarget().getName() = "Protect"   and algo = "dpapi-memory-protect"   or
    mc.getTarget().getName() = "Unprotect" and algo = "dpapi-memory-unprotect"
  )
}

// ---------------------------------------------------------------------------
// Miscellaneous security operations
// ---------------------------------------------------------------------------
predicate isOtherCryptoDetection(Expr call, string algo) {
  // --- CryptographicOperations.FixedTimeEquals — timing-safe comparison ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "FixedTimeEquals" and
    mc.getTarget().getDeclaringType().getName() = "CryptographicOperations" and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = "fixed-time-compare"
  )

  or

  // --- CryptographicOperations.ZeroMemory — secure memory clearing ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "ZeroMemory" and
    mc.getTarget().getDeclaringType().getName() = "CryptographicOperations" and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = "zero-memory"
  )
}

// ---------------------------------------------------------------------------
// String-driven algorithm factories
// ---------------------------------------------------------------------------
predicate isStringFactoryDetection(Expr call, string algo) {
  // CryptoConfig.CreateFromName("SHA256") / MapNameToOID("SHA256")
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = ["CreateFromName", "MapNameToOID"] and
    mc.getTarget().getDeclaringType().getName() = "CryptoConfig" and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )

  or

  // AsymmetricAlgorithm.Create("RSA") — legacy string factory
  exists(MethodCall mc, ValueOrRefType resolvedType |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "Create" and
    inSscNamespace(resolvedType) and
    (
      resolvedType = mc.getTarget().getDeclaringType() or
      resolvedType = mc.getQualifier().(TypeAccess).getTarget()
    ) and
    resolvedType.getName() = "AsymmetricAlgorithm" and
    mc.getNumberOfArguments() = 1 and
    algo = mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// Legacy signature / key-exchange formatters
// ---------------------------------------------------------------------------
predicate isFormatterDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType())
  |
    oc.getTarget().getDeclaringType().getName() =
      ["RSAPKCS1SignatureFormatter", "RSAPKCS1SignatureDeformatter"] and algo = "rsa-pkcs1-sign"
    or
    oc.getTarget().getDeclaringType().getName() =
      ["RSAOAEPKeyExchangeFormatter", "RSAOAEPKeyExchangeDeformatter"] and algo = "rsa-oaep-keyexchange"
    or
    oc.getTarget().getDeclaringType().getName() =
      ["RSAPKCS1KeyExchangeFormatter", "RSAPKCS1KeyExchangeDeformatter"] and algo = "rsa-pkcs1-keyexchange"
    or
    oc.getTarget().getDeclaringType().getName() =
      ["DSASignatureFormatter", "DSASignatureDeformatter"] and algo = "dsa-sign"
  )
}

// ---------------------------------------------------------------------------
// CMS / PKCS (System.Security.Cryptography.Pkcs)
// ---------------------------------------------------------------------------
predicate isCmsDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType())
  |
    oc.getTarget().getDeclaringType().getName() = "SignedCms"               and algo = "cms-signed"        or
    oc.getTarget().getDeclaringType().getName() = "EnvelopedCms"            and algo = "cms-enveloped"     or
    oc.getTarget().getDeclaringType().getName() = "CmsSigner"               and algo = "cms-signer"        or
    oc.getTarget().getDeclaringType().getName() = "CmsRecipient"            and algo = "cms-recipient"     or
    oc.getTarget().getDeclaringType().getName() = "Pkcs12Builder"           and algo = "pkcs12"            or
    oc.getTarget().getDeclaringType().getName() = "Rfc3161TimestampRequest" and algo = "rfc3161-timestamp"
  )

  or

  // Pkcs12Info and Pkcs8PrivateKeyInfo are only reachable through static factories
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = ["Create", "Decode", "DecryptAndDecode"] and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    mc.getTarget().getDeclaringType().getName() = "Pkcs12Info"          and algo = "pkcs12" or
    mc.getTarget().getDeclaringType().getName() = "Pkcs8PrivateKeyInfo" and algo = "pkcs8"
  )

  or

  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = ["SignedCms", "EnvelopedCms"] and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    mc.getTarget().getName() = "ComputeSignature" and algo = "cms-sign"    or
    mc.getTarget().getName() = "CheckSignature"   and algo = "cms-verify"  or
    mc.getTarget().getName() = "Encrypt"          and algo = "cms-encrypt" or
    mc.getTarget().getName() = "Decrypt"          and algo = "cms-decrypt"
  )

  or

  // Rfc3161TimestampRequest.CreateFromHash / CreateFromData / CreateFromSignerInfo
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getDeclaringType().getName() = "Rfc3161TimestampRequest" and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = "rfc3161-timestamp"
  )
}

// ---------------------------------------------------------------------------
// XML signature and encryption (System.Security.Cryptography.Xml)
// ---------------------------------------------------------------------------
predicate isXmlCryptoDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType())
  |
    oc.getTarget().getDeclaringType().getName() = "SignedXml"    and algo = "xmldsig" or
    oc.getTarget().getDeclaringType().getName() = "EncryptedXml" and algo = "xmlenc"
  )

  or

  exists(MethodCall mc |
    mc = call and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    mc.getTarget().getDeclaringType().getName() = "SignedXml" and
    mc.getTarget().getName() = "ComputeSignature" and algo = "xmldsig-sign"
    or
    mc.getTarget().getDeclaringType().getName() = "SignedXml" and
    mc.getTarget().getName() = "CheckSignature" and algo = "xmldsig-verify"
    or
    mc.getTarget().getDeclaringType().getName() = "EncryptedXml" and
    mc.getTarget().getName() = ["EncryptData", "EncryptKey", "Encrypt"] and algo = "xmlenc-encrypt"
    or
    mc.getTarget().getDeclaringType().getName() = "EncryptedXml" and
    mc.getTarget().getName() = ["DecryptData", "DecryptKey", "DecryptDocument"] and algo = "xmlenc-decrypt"
  )

  or

  // Algorithm URI constants identify the concrete primitive in use
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = ["SignedXml", "EncryptedXml"] and
    inSscNamespace(fa.getTarget().getDeclaringType())
  |
    fa.getTarget().getName() = "XmlDsigSHA1Url"             and algo = "sha1"                  or
    fa.getTarget().getName() = "XmlDsigSHA256Url"           and algo = "sha256"                or
    fa.getTarget().getName() = "XmlDsigSHA384Url"           and algo = "sha384"                or
    fa.getTarget().getName() = "XmlDsigSHA512Url"           and algo = "sha512"                or
    fa.getTarget().getName() = "XmlDsigHMACSHA1Url"         and algo = "hmac-sha1"             or
    fa.getTarget().getName() = "XmlDsigDSAUrl"              and algo = "dsa-sign"              or
    fa.getTarget().getName() = "XmlDsigRSASHA1Url"          and algo = "rsa-pkcs1-sign-sha1"   or
    fa.getTarget().getName() = "XmlDsigRSASHA256Url"        and algo = "rsa-pkcs1-sign-sha256" or
    fa.getTarget().getName() = "XmlDsigRSASHA384Url"        and algo = "rsa-pkcs1-sign-sha384" or
    fa.getTarget().getName() = "XmlDsigRSASHA512Url"        and algo = "rsa-pkcs1-sign-sha512" or
    fa.getTarget().getName() = "XmlEncAES128Url"            and algo = "aes-128-cbc"           or
    fa.getTarget().getName() = "XmlEncAES192Url"            and algo = "aes-192-cbc"           or
    fa.getTarget().getName() = "XmlEncAES256Url"            and algo = "aes-256-cbc"           or
    fa.getTarget().getName() = "XmlEncTripleDESUrl"         and algo = "3des-cbc"              or
    fa.getTarget().getName() = "XmlEncAES128KeyWrapUrl"     and algo = "aes-128-kw"            or
    fa.getTarget().getName() = "XmlEncAES192KeyWrapUrl"     and algo = "aes-192-kw"            or
    fa.getTarget().getName() = "XmlEncAES256KeyWrapUrl"     and algo = "aes-256-kw"            or
    fa.getTarget().getName() = "XmlEncTripleDESKeyWrapUrl"  and algo = "3des-kw"               or
    fa.getTarget().getName() = "XmlEncRSA15Url"             and algo = "rsa-pkcs1v15"          or
    fa.getTarget().getName() = "XmlEncRSAOAEPUrl"           and algo = "rsa-oaep"
  )
}

// ---------------------------------------------------------------------------
// Post-quantum cryptography: ML-DSA, ML-KEM, SLH-DSA (.NET 9/10+)
// ---------------------------------------------------------------------------
predicate isPqcDetection(Expr call, string algo) {
  // --- Key generation: MLDsa.GenerateKey(...) / MLKem.GenerateKey(...) / SlhDsa.GenerateKey(...) ---
  exists(MethodCall mc, string typeName, string label |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "GenerateKey" and
    typeName = mc.getTarget().getDeclaringType().getName() and
    pqcTypeLabel(typeName, label) and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    exists(string algName | pqcAlgoArg(mc.getArgument(0), algName) and algo = algName + "-keygen")
    or
    not exists(string a | pqcAlgoArg(mc.getArgument(0), a)) and algo = label + "-keygen"
  )

  or

  // --- ML-DSA / SLH-DSA signing (no separate hash/padding params — context bytes instead) ---
  exists(MethodCall mc, string typeName, string label |
    mc = call and
    mc.getTarget().getName() = ["SignData", "VerifyData", "TrySignData", "TryVerifyData"] and
    typeName = mc.getTarget().getDeclaringType().getName() and
    typeName = ["MLDsa", "SlhDsa"] and
    pqcTypeLabel(typeName, label) and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = label + "-sign"
  )

  or

  // --- ML-KEM encapsulation / decapsulation ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["Encapsulate", "Decapsulate"] and
    mc.getTarget().getDeclaringType().getName() = "MLKem" and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    algo = "ml-kem-" + mc.getTarget().getName().toLowerCase()
  )

  or

  // --- Key export operations (instance methods on the abstract base type) ---
  exists(MethodCall mc, string typeName, string label |
    mc = call and
    typeName = mc.getQualifier().getType().(ValueOrRefType).getABaseType*().getName() and
    pqcTypeLabel(typeName, label) and
    inSscNamespace(mc.getQualifier().getType().(ValueOrRefType)) and
    mc.getTarget().getName().matches("Export%") and
    algo = label + "-key-export"
  )

  or

  // --- Key import operations (static factories on the abstract base type) ---
  exists(MethodCall mc, string typeName, string label |
    mc = call and
    mc.getTarget().isStatic() and
    typeName = mc.getTarget().getDeclaringType().getName() and
    pqcTypeLabel(typeName, label) and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    mc.getTarget().getName().matches("Import%") and
    algo = label + "-key-import"
  )
}

// ---------------------------------------------------------------------------
// KMAC (.NET 9+), including the KmacXof extendable-output variants
// ---------------------------------------------------------------------------
predicate isKmacDetection(Expr call, string algo) {
  // --- Constructors: new Kmac128(key, ...) / new Kmac256(key, ...) / new KmacXof128(...) / new KmacXof256(...) ---
  exists(ObjectCreation oc |
    oc = call and
    inSscNamespace(oc.getTarget().getDeclaringType())
  |
    oc.getTarget().getDeclaringType().getName() = "Kmac128"    and algo = "kmac128"    or
    oc.getTarget().getDeclaringType().getName() = "Kmac256"    and algo = "kmac256"    or
    oc.getTarget().getDeclaringType().getName() = "KmacXof128" and algo = "kmac-xof128" or
    oc.getTarget().getDeclaringType().getName() = "KmacXof256" and algo = "kmac-xof256"
  )

  or

  // --- Static one-shot: Kmac128.HashData(...) / KmacXof128.HashData(...) etc. ---
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().isStatic() and
    mc.getTarget().getName() = "HashData" and
    inSscNamespace(mc.getTarget().getDeclaringType())
  |
    mc.getTarget().getDeclaringType().getName() = "Kmac128"    and algo = "kmac128"    or
    mc.getTarget().getDeclaringType().getName() = "Kmac256"    and algo = "kmac256"    or
    mc.getTarget().getDeclaringType().getName() = "KmacXof128" and algo = "kmac-xof128" or
    mc.getTarget().getDeclaringType().getName() = "KmacXof256" and algo = "kmac-xof256"
  )

  or

  // --- Instance streaming operations ---
  exists(MethodCall mc, string typeName |
    mc = call and
    mc.getTarget().getName() = ["AppendData", "GetCurrentHash", "GetHashAndReset"] and
    typeName = mc.getTarget().getDeclaringType().getName() and
    typeName = ["Kmac128", "Kmac256", "KmacXof128", "KmacXof256"] and
    inSscNamespace(mc.getTarget().getDeclaringType()) and
    (
      typeName = "Kmac128" and algo = "kmac128" or
      typeName = "Kmac256" and algo = "kmac256" or
      typeName = "KmacXof128" and algo = "kmac-xof128" or
      typeName = "KmacXof256" and algo = "kmac-xof256"
    )
  )
}

// ---------------------------------------------------------------------------
// Password-based encryption parameters (PbeParameters / PbeEncryptionAlgorithm)
// ---------------------------------------------------------------------------
predicate isPbeDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    oc.getTarget().getDeclaringType().getName() = "PbeParameters" and
    inSscNamespace(oc.getTarget().getDeclaringType())
  |
    exists(string encAlgo, string hashName |
      pbeAlgoArg(oc.getArgument(0), encAlgo) and
      hashAlgoArg(oc.getArgument(1), hashName) and
      algo = "pbe-" + encAlgo + "-" + hashName
    )
    or
    not (
      exists(string e | pbeAlgoArg(oc.getArgument(0), e)) and
      exists(string h | hashAlgoArg(oc.getArgument(1), h))
    ) and
    algo = "pbe-params"
  )
}

// =============================================================================
// Main query
// =============================================================================

from Expr call, string algo, string api
where
  api = "System.Security.Cryptography" and
  (
    isHashDetection(call, algo) or
    isHmacDetection(call, algo) or
    isSymmetricDetection(call, algo) or
    isSymmetricEncryptionDetection(call, algo) or
    isSymmetricOneShotDetection(call, algo) or
    isCipherModeConfigDetection(call, algo) or
    isKeySizeDetection(call, algo) or
    isRsaDetection(call, algo) or
    isEcdsaDetection(call, algo) or
    isEcdhDetection(call, algo) or
    isDsaDetection(call, algo) or
    isKdfDetection(call, algo) or
    isRandomDetection(call, algo) or
    isPkiDetection(call, algo) or
    isDpapiDetection(call, algo) or
    isStringFactoryDetection(call, algo) or
    isFormatterDetection(call, algo) or
    isCmsDetection(call, algo) or
    isXmlCryptoDetection(call, algo) or
    isPqcDetection(call, algo) or
    isKmacDetection(call, algo) or
    isPbeDetection(call, algo) or
    isOtherCryptoDetection(call, algo)
  )
select call, "algo=" + algo + ", api=" + api
