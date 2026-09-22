/**
 * @name Crypto inventory — Microsoft.AspNetCore.DataProtection (C#/.NET)
 * @description Inventory of Microsoft.AspNetCore.DataProtection usage including
 *              data protect/unprotect operations, time-limited protection, provider
 *              and protector creation, low-level authenticated encryption, key
 *              management, algorithm configuration (AES-CBC, AES-GCM, HMAC),
 *              Windows DPAPI/CNG, X.509 certificate key encryption, and data
 *              protection service registration.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/csharp-cbom-aspnetcore-dataprotection
 * @tags security
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow

// Note: namespace guards are intentionally omitted — in --build-mode=none,
// NuGet types are unresolved so getNamespace().getFullName() returns "".
// Detection relies on class/interface names alone, which are sufficiently distinctive.

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
// Detection predicates
// =============================================================================

// ---------------------------------------------------------------------------
// Core protect / unprotect operations
// ---------------------------------------------------------------------------
predicate isProtectDetection(Expr call, string algo) {
  // IDataProtector.Protect(byte[] plaintext) / string extension overload
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "Protect" and
    mc.getTarget().getDeclaringType().getName() =
      ["IDataProtector", "DataProtectionCommonExtensions"] and
    algo = "aspnetcore-dp-protect"
  )

  or

  // IDataProtector.Unprotect(byte[] protectedData) / string extension overload
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "Unprotect" and
    mc.getTarget().getDeclaringType().getName() =
      ["IDataProtector", "DataProtectionCommonExtensions"] and
    algo = "aspnetcore-dp-unprotect"
  )
}

// ---------------------------------------------------------------------------
// Time-limited protection
// ---------------------------------------------------------------------------
predicate isTimeLimitedDetection(Expr call, string algo) {
  // ITimeLimitedDataProtector.Protect(byte[], DateTimeOffset) — expiry-bounded encryption
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "Protect" and
    mc.getTarget().getDeclaringType().getName() =
      ["ITimeLimitedDataProtector", "TimeLimitedDataProtectorExtensions"] and
    algo = "aspnetcore-dp-timelimited-protect"
  )

  or

  // ITimeLimitedDataProtector.Unprotect — decrypts and validates expiry
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "Unprotect" and
    mc.getTarget().getDeclaringType().getName() =
      ["ITimeLimitedDataProtector", "TimeLimitedDataProtectorExtensions"] and
    algo = "aspnetcore-dp-timelimited-unprotect"
  )

  or

  // ToTimeLimitedDataProtector() — wraps an IDataProtector with token expiry semantics
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "ToTimeLimitedDataProtector" and
    algo = "aspnetcore-dp-timelimited"
  )
}

// ---------------------------------------------------------------------------
// Provider and protector creation
// ---------------------------------------------------------------------------
predicate isProviderDetection(Expr call, string algo) {
  // new DataProtectionProvider(DirectoryInfo, ...) — file-system-backed key ring provider
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "DataProtectionProvider" and
    algo = "aspnetcore-dp-provider"
  )

  or

  // new EphemeralDataProtectionProvider() — in-memory provider, keys never persisted
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "EphemeralDataProtectionProvider" and
    algo = "aspnetcore-dp-ephemeral-provider"
  )

  or

  // IDataProtectionProvider.CreateProtector(string purpose) — scoped protector creation
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "CreateProtector" and
    mc.getTarget().getDeclaringType().getName() =
      ["IDataProtectionProvider", "DataProtectionCommonExtensions"] and
    algo = "aspnetcore-dp-create-protector"
  )
}

// ---------------------------------------------------------------------------
// Low-level authenticated encryption (IAuthenticatedEncryptor)
// ---------------------------------------------------------------------------
predicate isAuthEncryptorDetection(Expr call, string algo) {
  // IAuthenticatedEncryptor.Encrypt(plaintext, additionalAuthenticatedData)
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "Encrypt" and
    mc.getTarget().getDeclaringType().getName() = "IAuthenticatedEncryptor" and
    algo = "aspnetcore-dp-auth-encrypt"
  )

  or

  // IAuthenticatedEncryptor.Decrypt(ciphertext, additionalAuthenticatedData)
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "Decrypt" and
    mc.getTarget().getDeclaringType().getName() = "IAuthenticatedEncryptor" and
    algo = "aspnetcore-dp-auth-decrypt"
  )
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------
predicate isKeyManagementDetection(Expr call, string algo) {
  // IKeyManager.CreateNewKey(activationDate, expirationDate) — generates and persists a new key
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "CreateNewKey" and
    mc.getTarget().getDeclaringType().getName() = ["IKeyManager", "XmlKeyManager"] and
    algo = "aspnetcore-dp-key-create"
  )

  or

  // IKeyManager.RevokeKey(keyId, reason) — revokes a single key by GUID
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "RevokeKey" and
    mc.getTarget().getDeclaringType().getName() = ["IKeyManager", "XmlKeyManager"] and
    algo = "aspnetcore-dp-key-revoke"
  )

  or

  // IKeyManager.RevokeAllKeys(revocationDate, reason) — bulk key revocation
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "RevokeAllKeys" and
    mc.getTarget().getDeclaringType().getName() = ["IKeyManager", "XmlKeyManager"] and
    algo = "aspnetcore-dp-key-revoke-all"
  )

  or

  // IKeyManager.GetAllKeys() — retrieves the active key ring
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "GetAllKeys" and
    mc.getTarget().getDeclaringType().getName() = ["IKeyManager", "XmlKeyManager"] and
    algo = "aspnetcore-dp-key-list"
  )

  or

  // new XmlKeyManager(...) — concrete key manager that persists keys as XML
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "XmlKeyManager" and
    algo = "aspnetcore-dp-key-manager"
  )
}

// ---------------------------------------------------------------------------
// Algorithm configuration
// ---------------------------------------------------------------------------
predicate isAlgorithmConfigDetection(Expr call, string algo) {
  // new AuthenticatedEncryptorConfiguration() — configures EncryptionAlgorithm + ValidationAlgorithm
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "AuthenticatedEncryptorConfiguration" and
    algo = "aspnetcore-dp-encryptor-config"
  )

  or

  // EncryptionAlgorithm enum member — identifies the configured AES mode and key size
  exists(FieldAccess fa |
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "EncryptionAlgorithm"
  |
    fa.getTarget().getName() = "AES_128_CBC" and algo = "aes-128-cbc" or
    fa.getTarget().getName() = "AES_192_CBC" and algo = "aes-192-cbc" or
    fa.getTarget().getName() = "AES_256_CBC" and algo = "aes-256-cbc" or
    fa.getTarget().getName() = "AES_128_GCM" and algo = "aes-128-gcm" or
    fa.getTarget().getName() = "AES_192_GCM" and algo = "aes-192-gcm" or
    fa.getTarget().getName() = "AES_256_GCM" and algo = "aes-256-gcm"
  )

  or

  // ValidationAlgorithm enum member — identifies the configured HMAC primitive
  exists(FieldAccess fa |
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "ValidationAlgorithm"
  |
    fa.getTarget().getName() = "HMACSHA256" and algo = "hmac-sha256" or
    fa.getTarget().getName() = "HMACSHA512" and algo = "hmac-sha512"
  )

  or

  // new ManagedAuthenticatedEncryptorConfiguration() — uses .NET managed algorithm types
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "ManagedAuthenticatedEncryptorConfiguration" and
    algo = "aspnetcore-dp-managed-encryptor-config"
  )

  or

  // new CngCbcAuthenticatedEncryptorConfiguration() — Windows CNG CBC-mode encryption
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "CngCbcAuthenticatedEncryptorConfiguration" and
    algo = "aspnetcore-dp-cng-cbc-config"
  )

  or

  // new CngGcmAuthenticatedEncryptorConfiguration() — Windows CNG GCM-mode encryption
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "CngGcmAuthenticatedEncryptorConfiguration" and
    algo = "aspnetcore-dp-cng-gcm-config"
  )
}

// ---------------------------------------------------------------------------
// Concrete algorithms selected on an encryptor configuration object
// Managed configurations carry CLR types (typeof(Aes)); CNG configurations carry
// BCrypt algorithm name strings ("AES", "SHA256") plus explicit key sizes.
// ---------------------------------------------------------------------------
predicate isEncryptorConfigPropertyDetection(Expr call, string algo) {
  exists(ValueOrRefType target, string prop, Expr value |
    propertyConfig(call, target, prop, value) and
    target.getName() = [
      "AuthenticatedEncryptorConfiguration",
      "ManagedAuthenticatedEncryptorConfiguration",
      "CngCbcAuthenticatedEncryptorConfiguration",
      "CngGcmAuthenticatedEncryptorConfiguration"
    ]
  |
    // EncryptionAlgorithmType = typeof(Aes) / ValidationAlgorithmType = typeof(HMACSHA256)
    prop = ["EncryptionAlgorithmType", "ValidationAlgorithmType"] and
    algo = value.(TypeofExpr).getTypeAccess().getTarget().getName().toLowerCase()
    or
    // CNG configurations name the algorithm and provider as strings
    prop = ["EncryptionAlgorithm", "HashAlgorithm"] and
    algo = value.(StringLiteral).getValue().toLowerCase()
    or
    prop = ["EncryptionAlgorithmProvider", "HashAlgorithmProvider"] and
    algo = "aspnetcore-dp-cng-provider:" + value.(StringLiteral).getValue().toLowerCase()
    or
    prop = ["EncryptionAlgorithmKeySize", "ValidationAlgorithmKeySize"] and
    algo = "aspnetcore-dp-keysize-" + value.(Literal).getValue()
  )
}

// ---------------------------------------------------------------------------
// Fluent algorithm selection on IDataProtectionBuilder
// ---------------------------------------------------------------------------
predicate isBuilderAlgorithmDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "UseCryptographicAlgorithms" and
    algo = "aspnetcore-dp-algorithms"
  )

  or

  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "UseCustomCryptographicAlgorithms" and
    algo = "aspnetcore-dp-custom-algorithms"
  )
}

// ---------------------------------------------------------------------------
// XML key encryption providers (key-at-rest protection)
// ---------------------------------------------------------------------------
predicate isXmlKeyEncryptionDetection(Expr call, string algo) {
  // new DpapiXmlEncryptor(...) — Windows DPAPI (machine/user scope) key XML encryption
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "DpapiXmlEncryptor" and
    algo = "aspnetcore-dp-dpapi-xml-encryptor"
  )

  or

  // new DpapiNGXmlEncryptor(...) — Windows DPAPI-NG descriptor-based key XML encryption
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "DpapiNGXmlEncryptor" and
    algo = "aspnetcore-dp-dpapi-ng-xml-encryptor"
  )

  or

  // new CertificateXmlEncryptor(...) — X.509 certificate key XML encryption
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "CertificateXmlEncryptor" and
    algo = "aspnetcore-dp-cert-xml-encryptor"
  )

  or

  // IXmlEncryptor.Encrypt(XElement) — raw key XML encryption call
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "Encrypt" and
    mc.getTarget().getDeclaringType().getName() = "IXmlEncryptor" and
    algo = "aspnetcore-dp-xml-encrypt"
  )

  or

  // IXmlDecryptor.Decrypt(XElement) — raw key XML decryption call
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "Decrypt" and
    mc.getTarget().getDeclaringType().getName() = "IXmlDecryptor" and
    algo = "aspnetcore-dp-xml-decrypt"
  )
}

// ---------------------------------------------------------------------------
// Service registration and fluent builder configuration
// ---------------------------------------------------------------------------
predicate isServiceRegistrationDetection(Expr call, string algo) {
  // AddDataProtection() — registers the DataProtection system with the DI container
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "AddDataProtection" and
    algo = "aspnetcore-dp-configure"
  )

  or

  // PersistKeysToFileSystem — stores key ring XML on the local file system
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = "PersistKeysToFileSystem" and
    algo = "aspnetcore-dp-key-persist-filesystem"
  )

  or

  // PersistKeysToAzureBlobStorage — stores key ring XML in Azure Blob Storage
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = "PersistKeysToAzureBlobStorage" and
    algo = "aspnetcore-dp-key-persist-azure-blob"
  )

  or

  // PersistKeysToDbContext — stores key ring XML via Entity Framework Core
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = "PersistKeysToDbContext" and
    algo = "aspnetcore-dp-key-persist-ef-core"
  )

  or

  // PersistKeysToStackExchangeRedis — stores key ring XML in Redis
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = "PersistKeysToStackExchangeRedis" and
    algo = "aspnetcore-dp-key-persist-redis"
  )

  or

  // PersistKeysToRegistry — stores key ring XML in the Windows registry
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getUndecoratedName() = "PersistKeysToRegistry" and
    algo = "aspnetcore-dp-key-persist-registry"
  )

  or

  // ProtectKeysWithCertificate — encrypts key XML at rest using an X.509 certificate
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "ProtectKeysWithCertificate" and
    algo = "aspnetcore-dp-key-protect-certificate"
  )

  or

  // ProtectKeysWithAzureKeyVault — encrypts key XML at rest using Azure Key Vault
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "ProtectKeysWithAzureKeyVault" and
    algo = "aspnetcore-dp-key-protect-azure-key-vault"
  )

  or

  // ProtectKeysWithDpapi — encrypts key XML at rest using Windows DPAPI
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "ProtectKeysWithDpapi" and
    algo = "aspnetcore-dp-key-protect-dpapi"
  )

  or

  // ProtectKeysWithDpapiNG — encrypts key XML at rest using Windows DPAPI-NG
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "ProtectKeysWithDpapiNG" and
    algo = "aspnetcore-dp-key-protect-dpapi-ng"
  )

  or

  // SetDefaultKeyLifetime — configures how long each generated key remains active
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "SetDefaultKeyLifetime" and
    algo = "aspnetcore-dp-key-lifetime"
  )

  or

  // DisableAutomaticKeyGeneration — suppresses the automatic key ring rotation policy
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "DisableAutomaticKeyGeneration" and
    algo = "aspnetcore-dp-key-no-autogen"
  )

  or

  // SetApplicationName — scopes the data protection system to a named application boundary
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "SetApplicationName" and
    algo = "aspnetcore-dp-app-scope"
  )

  or

  // UseEphemeralDataProtectionProvider — forces in-memory (non-persistent) key storage in DI
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "UseEphemeralDataProtectionProvider" and
    algo = "aspnetcore-dp-ephemeral"
  )
}

// =============================================================================
// Main query
// =============================================================================

from Expr call, string algo, string api
where
  api = "Microsoft.AspNetCore.DataProtection" and
  (
    isProtectDetection(call, algo) or
    isTimeLimitedDetection(call, algo) or
    isProviderDetection(call, algo) or
    isAuthEncryptorDetection(call, algo) or
    isKeyManagementDetection(call, algo) or
    isAlgorithmConfigDetection(call, algo) or
    isEncryptorConfigPropertyDetection(call, algo) or
    isBuilderAlgorithmDetection(call, algo) or
    isXmlKeyEncryptionDetection(call, algo) or
    isServiceRegistrationDetection(call, algo)
  )
select call, "algo=" + algo + ", api=" + api
