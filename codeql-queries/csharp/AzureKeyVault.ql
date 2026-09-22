/**
 * @name Crypto inventory — Azure Key Vault (C#/.NET)
 * @description Inventory of Azure.Security.KeyVault cryptographic API usage including
 *              CryptographyClient encrypt/decrypt/sign/verify/wrap/unwrap operations,
 *              KeyClient key lifecycle management, EncryptionAlgorithm / SignatureAlgorithm /
 *              KeyWrapAlgorithm / KeyType configuration, and Secrets / Certificates clients.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/csharp-cbom-azure-keyvault
 * @tags security
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow

// Note: namespace guards are intentionally omitted — in --build-mode=none,
// NuGet types are unresolved so getNamespace().getFullName() returns "".
// Detection relies on class/struct names alone, which are sufficiently distinctive.

// =============================================================================
// Detection predicates
// =============================================================================

// ---------------------------------------------------------------------------
// Client construction
// ---------------------------------------------------------------------------
predicate isClientCreationDetection(Expr call, string algo) {
  // new CryptographyClient(...) — client for cryptographic operations against a Key Vault key
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "CryptographyClient" and
    algo = "akvault-cryptography-client"
  )
  or
  // new KeyClient(...) — client for key lifecycle management in Key Vault
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "KeyClient" and
    algo = "akvault-key-client"
  )
  or
  // new SecretClient(...) — client for secret management in Key Vault
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "SecretClient" and
    algo = "akvault-secret-client"
  )
  or
  // new CertificateClient(...) — client for certificate management in Key Vault
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "CertificateClient" and
    algo = "akvault-certificate-client"
  )
}

// ---------------------------------------------------------------------------
// Encryption and decryption (CryptographyClient)
// ---------------------------------------------------------------------------
predicate isCryptoOperationDetection(Expr call, string algo) {
  // CryptographyClient.Encrypt — asymmetric (RSA-OAEP) or symmetric (AES-GCM/CBC) encryption via Key Vault
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["Encrypt", "EncryptAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CryptographyClient" and
    algo = "akvault-encrypt"
  )
  or
  // CryptographyClient.Decrypt — decrypts data previously encrypted by this key
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["Decrypt", "DecryptAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CryptographyClient" and
    algo = "akvault-decrypt"
  )
}

// ---------------------------------------------------------------------------
// Signing and verification (CryptographyClient)
// ---------------------------------------------------------------------------
predicate isSignVerifyDetection(Expr call, string algo) {
  // CryptographyClient.Sign — signs a pre-computed digest using RSA-PKCS1 / RSA-PSS / ECDSA
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["Sign", "SignAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CryptographyClient" and
    algo = "akvault-sign"
  )
  or
  // CryptographyClient.SignData — hashes and signs raw data (combines hash + sign)
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["SignData", "SignDataAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CryptographyClient" and
    algo = "akvault-sign-data"
  )
  or
  // CryptographyClient.Verify — verifies a signature over a pre-computed digest
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["Verify", "VerifyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CryptographyClient" and
    algo = "akvault-verify"
  )
  or
  // CryptographyClient.VerifyData — hashes and verifies a signature over raw data
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["VerifyData", "VerifyDataAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CryptographyClient" and
    algo = "akvault-verify-data"
  )
}

// ---------------------------------------------------------------------------
// Key wrapping (CryptographyClient)
// ---------------------------------------------------------------------------
predicate isKeyWrapDetection(Expr call, string algo) {
  // CryptographyClient.WrapKey — encrypts a symmetric key for secure transport
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["WrapKey", "WrapKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CryptographyClient" and
    algo = "akvault-wrap-key"
  )
  or
  // CryptographyClient.UnwrapKey — decrypts a wrapped symmetric key
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["UnwrapKey", "UnwrapKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CryptographyClient" and
    algo = "akvault-unwrap-key"
  )
}

// ---------------------------------------------------------------------------
// Key lifecycle management (KeyClient)
// ---------------------------------------------------------------------------
predicate isKeyManagementDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["CreateKey", "CreateKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-create-key"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["CreateRsaKey", "CreateRsaKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-create-rsa-key"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["CreateEcKey", "CreateEcKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-create-ec-key"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["CreateOctKey", "CreateOctKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-create-oct-key"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["ImportKey", "ImportKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-import-key"
  )
  or
  // RotateKey — creates a new key version according to the key rotation policy
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["RotateKey", "RotateKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-rotate-key"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["GetKey", "GetKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-get-key"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["DeleteKey", "DeleteKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-delete-key"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["UpdateKeyProperties", "UpdateKeyPropertiesAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-update-key"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["BackupKey", "BackupKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-backup-key"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["RestoreKeyBackup", "RestoreKeyBackupAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-restore-key"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["RecoverDeletedKey", "RecoverDeletedKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-recover-key"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["PurgeDeletedKey", "PurgeDeletedKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-purge-key"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["GetKeyRotationPolicy", "GetKeyRotationPolicyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-get-rotation-policy"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["UpdateKeyRotationPolicy", "UpdateKeyRotationPolicyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-update-rotation-policy"
  )
  or
  // GetRandomBytes — HSM-backed cryptographically secure random number generation
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["GetRandomBytes", "GetRandomBytesAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-csprng"
  )
  or
  // ReleaseKey — attestation-bound secure key release/export
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["ReleaseKey", "ReleaseKeyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "KeyClient" and
    algo = "akvault-release-key"
  )
}

// ---------------------------------------------------------------------------
// Key creation options (carries key type and parameter configuration)
// ---------------------------------------------------------------------------
predicate isKeyOptionsDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "CreateRsaKeyOptions" and
    algo = "akvault-rsa-key-options"
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "CreateEcKeyOptions" and
    algo = "akvault-ec-key-options"
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "CreateOctKeyOptions" and
    algo = "akvault-oct-key-options"
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "ImportKeyOptions" and
    algo = "akvault-import-key-options"
  )
}

// ---------------------------------------------------------------------------
// EncryptionAlgorithm struct field access
// ---------------------------------------------------------------------------
predicate isEncryptionAlgorithmDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "EncryptionAlgorithm"
  |
    fa.getTarget().getName() = "Rsa15"      and algo = "rsa-1_5"         or
    fa.getTarget().getName() = "RsaOaep"    and algo = "rsa-oaep"        or
    fa.getTarget().getName() = "RsaOaep256" and algo = "rsa-oaep-256"    or
    fa.getTarget().getName() = "A128Gcm"    and algo = "aes-128-gcm"     or
    fa.getTarget().getName() = "A192Gcm"    and algo = "aes-192-gcm"     or
    fa.getTarget().getName() = "A256Gcm"    and algo = "aes-256-gcm"     or
    fa.getTarget().getName() = "A128CbcPad" and algo = "aes-128-cbc-pad" or
    fa.getTarget().getName() = "A192CbcPad" and algo = "aes-192-cbc-pad" or
    fa.getTarget().getName() = "A256CbcPad" and algo = "aes-256-cbc-pad" or
    fa.getTarget().getName() = "A128Cbc"    and algo = "aes-128-cbc"     or
    fa.getTarget().getName() = "A192Cbc"    and algo = "aes-192-cbc"     or
    fa.getTarget().getName() = "A256Cbc"    and algo = "aes-256-cbc"
  )
}

// ---------------------------------------------------------------------------
// SignatureAlgorithm struct field access
// ---------------------------------------------------------------------------
predicate isSignatureAlgorithmDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "SignatureAlgorithm"
  |
    fa.getTarget().getName() = "RS256"  and algo = "rs256"  or
    fa.getTarget().getName() = "RS384"  and algo = "rs384"  or
    fa.getTarget().getName() = "RS512"  and algo = "rs512"  or
    fa.getTarget().getName() = "PS256"  and algo = "ps256"  or
    fa.getTarget().getName() = "PS384"  and algo = "ps384"  or
    fa.getTarget().getName() = "PS512"  and algo = "ps512"  or
    fa.getTarget().getName() = "ES256"  and algo = "es256"  or
    fa.getTarget().getName() = "ES384"  and algo = "es384"  or
    fa.getTarget().getName() = "ES512"  and algo = "es512"  or
    fa.getTarget().getName() = "ES256K" and algo = "es256k"
  )
}

// ---------------------------------------------------------------------------
// KeyWrapAlgorithm struct field access
// ---------------------------------------------------------------------------
predicate isKeyWrapAlgorithmDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "KeyWrapAlgorithm"
  |
    fa.getTarget().getName() = "Rsa15"      and algo = "rsa-1_5-wrap"      or
    fa.getTarget().getName() = "RsaOaep"    and algo = "rsa-oaep-wrap"     or
    fa.getTarget().getName() = "RsaOaep256" and algo = "rsa-oaep-256-wrap" or
    fa.getTarget().getName() = "A128KW"     and algo = "aes-128-kw"        or
    fa.getTarget().getName() = "A192KW"     and algo = "aes-192-kw"        or
    fa.getTarget().getName() = "A256KW"     and algo = "aes-256-kw"
  )
}

// ---------------------------------------------------------------------------
// KeyType struct field access
// ---------------------------------------------------------------------------
predicate isKeyTypeDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "KeyType"
  |
    fa.getTarget().getName() = "Rsa"    and algo = "rsa"     or
    fa.getTarget().getName() = "RsaHsm" and algo = "rsa-hsm" or
    fa.getTarget().getName() = "Ec"     and algo = "ec"      or
    fa.getTarget().getName() = "EcHsm"  and algo = "ec-hsm"  or
    fa.getTarget().getName() = "Oct"    and algo = "aes"     or
    fa.getTarget().getName() = "OctHsm" and algo = "aes-hsm"
  )
}

// ---------------------------------------------------------------------------
// Secrets operations (SecretClient)
// ---------------------------------------------------------------------------
predicate isSecretsOperationDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["GetSecret", "GetSecretAsync"] and
    mc.getTarget().getDeclaringType().getName() = "SecretClient" and
    algo = "akvault-get-secret"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["SetSecret", "SetSecretAsync"] and
    mc.getTarget().getDeclaringType().getName() = "SecretClient" and
    algo = "akvault-set-secret"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() =
      ["DeleteSecret", "DeleteSecretAsync", "StartDeleteSecret", "StartDeleteSecretAsync"] and
    mc.getTarget().getDeclaringType().getName() = "SecretClient" and
    algo = "akvault-delete-secret"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["UpdateSecretProperties", "UpdateSecretPropertiesAsync"] and
    mc.getTarget().getDeclaringType().getName() = "SecretClient" and
    algo = "akvault-update-secret"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["BackupSecret", "BackupSecretAsync"] and
    mc.getTarget().getDeclaringType().getName() = "SecretClient" and
    algo = "akvault-backup-secret"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["RestoreSecretBackup", "RestoreSecretBackupAsync"] and
    mc.getTarget().getDeclaringType().getName() = "SecretClient" and
    algo = "akvault-restore-secret"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() =
      ["RecoverDeletedSecret", "StartRecoverDeletedSecret", "StartRecoverDeletedSecretAsync"] and
    mc.getTarget().getDeclaringType().getName() = "SecretClient" and
    algo = "akvault-recover-secret"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["PurgeDeletedSecret", "PurgeDeletedSecretAsync"] and
    mc.getTarget().getDeclaringType().getName() = "SecretClient" and
    algo = "akvault-purge-secret"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["GetDeletedSecret", "GetDeletedSecretAsync"] and
    mc.getTarget().getDeclaringType().getName() = "SecretClient" and
    algo = "akvault-get-deleted-secret"
  )
}

// ---------------------------------------------------------------------------
// Certificate operations (CertificateClient)
// ---------------------------------------------------------------------------
predicate isCertificateOperationDetection(Expr call, string algo) {
  // StartCreateCertificate — initiates async certificate creation with policy
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["StartCreateCertificate", "StartCreateCertificateAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-create-certificate"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["GetCertificate", "GetCertificateAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-get-certificate"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["ImportCertificate", "ImportCertificateAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-import-certificate"
  )
  or
  // MergeCertificate — merges a CA-signed certificate into a pending CSR, completing the key pair
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["MergeCertificate", "MergeCertificateAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-merge-certificate"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["GetCertificatePolicy", "GetCertificatePolicyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-get-certificate-policy"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["UpdateCertificatePolicy", "UpdateCertificatePolicyAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-update-certificate-policy"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["BackupCertificate", "BackupCertificateAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-backup-certificate"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["RestoreCertificateBackup", "RestoreCertificateBackupAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-restore-certificate"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() =
      ["DeleteCertificate", "StartDeleteCertificate", "StartDeleteCertificateAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-delete-certificate"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = [
        "RecoverDeletedCertificate", "StartRecoverDeletedCertificate",
        "StartRecoverDeletedCertificateAsync"
      ] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-recover-certificate"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["PurgeDeletedCertificate", "PurgeDeletedCertificateAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-purge-certificate"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["GetCertificateOperation", "GetCertificateOperationAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-get-certificate-operation"
  )
  or
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["CancelCertificateOperation", "CancelCertificateOperationAsync"] and
    mc.getTarget().getDeclaringType().getName() = "CertificateClient" and
    algo = "akvault-cancel-certificate-operation"
  )
}

// ---------------------------------------------------------------------------
// Certificate policy — the key algorithm underlying a Key Vault certificate
// ---------------------------------------------------------------------------
predicate isCertificatePolicyDetection(Expr call, string algo) {
  // new CertificatePolicy(...) — policy governing certificate creation/renewal
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "CertificatePolicy" and
    algo = "akvault-certificate-policy"
  )
  or
  // CertificateKeyType — Rsa/RsaHsm/Ec/EcHsm/Oct/OctHsm, mirrors KeyType but is a distinct struct
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "CertificateKeyType"
  |
    fa.getTarget().getName() = "Rsa"    and algo = "rsa"     or
    fa.getTarget().getName() = "RsaHsm" and algo = "rsa-hsm" or
    fa.getTarget().getName() = "Ec"     and algo = "ec"      or
    fa.getTarget().getName() = "EcHsm"  and algo = "ec-hsm"  or
    fa.getTarget().getName() = "Oct"    and algo = "aes"     or
    fa.getTarget().getName() = "OctHsm" and algo = "aes-hsm"
  )
  or
  // CertificateKeyCurveName — mirrors KeyCurveName but is a distinct struct
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "CertificateKeyCurveName"
  |
    fa.getTarget().getName() = "P256"  and algo = "ec-p256"      or
    fa.getTarget().getName() = "P384"  and algo = "ec-p384"      or
    fa.getTarget().getName() = "P521"  and algo = "ec-p521"      or
    fa.getTarget().getName() = "P256K" and algo = "ec-secp256k1"
  )
  or
  // CertificateContentType — the export/import container format for the certificate's private key
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "CertificateContentType"
  |
    fa.getTarget().getName() = "Pkcs12" and algo = "pkcs12" or
    fa.getTarget().getName() = "Pem"    and algo = "pem"
  )
}

// ---------------------------------------------------------------------------
// KeyCurveName struct field access — the curve behind an EC key
// ---------------------------------------------------------------------------
predicate isKeyCurveDetection(Expr call, string algo) {
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = "KeyCurveName"
  |
    fa.getTarget().getName() = "P256"  and algo = "ec-p256"      or
    fa.getTarget().getName() = "P384"  and algo = "ec-p384"      or
    fa.getTarget().getName() = "P521"  and algo = "ec-p521"      or
    fa.getTarget().getName() = "P256K" and algo = "ec-secp256k1"
  )
}

// ---------------------------------------------------------------------------
// Algorithm identifiers constructed from strings
// The Azure SDK exposes these as extensible enum structs, so `new
// EncryptionAlgorithm("RSA-OAEP-256")` is an equally valid way to select one.
// ---------------------------------------------------------------------------
predicate isAlgorithmStringDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() =
      ["EncryptionAlgorithm", "SignatureAlgorithm", "KeyWrapAlgorithm", "KeyCurveName", "KeyType"] and
    algo = "akvault:" + oc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// EncryptParameters / DecryptParameters static factories
// These are the modern, AAD-aware way of selecting the content-encryption
// algorithm and carry the algorithm in the factory name itself.
// ---------------------------------------------------------------------------
predicate isEncryptParametersDetection(Expr call, string algo) {
  exists(MethodCall mc, string factory |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = ["EncryptParameters", "DecryptParameters"] and
    factory = mc.getTarget().getName()
  |
    factory = ["Rsa15Parameters", "Rsa15"]                and algo = "rsa-1_5"         or
    factory = ["RsaOaepParameters", "RsaOaep"]            and algo = "rsa-oaep"        or
    factory = ["RsaOaep256Parameters", "RsaOaep256"]      and algo = "rsa-oaep-256"    or
    factory = "A128GcmParameters"                         and algo = "aes-128-gcm"     or
    factory = "A192GcmParameters"                         and algo = "aes-192-gcm"     or
    factory = "A256GcmParameters"                         and algo = "aes-256-gcm"     or
    factory = "A128CbcParameters"                         and algo = "aes-128-cbc"     or
    factory = "A192CbcParameters"                         and algo = "aes-192-cbc"     or
    factory = "A256CbcParameters"                         and algo = "aes-256-cbc"     or
    factory = "A128CbcPadParameters"                      and algo = "aes-128-cbc-pad" or
    factory = "A192CbcPadParameters"                      and algo = "aes-192-cbc-pad" or
    factory = "A256CbcPadParameters"                      and algo = "aes-256-cbc-pad"
  )

  or

  // Static property form: EncryptParameters.A256GcmParameters is a method in the
  // SDK, but the equivalent property spelling is used by some SDK versions.
  exists(PropertyAccess pa |
    pa instanceof AssignableRead and
    pa = call and
    pa.getTarget().getDeclaringType().getName() = ["EncryptParameters", "DecryptParameters"] and
    algo = "akvault-params:" + pa.getTarget().getName().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// Explicit key sizes on key creation options
// ---------------------------------------------------------------------------

/**
 * Holds if `e` is an integer literal with value `v`, looking through the implicit
 * conversion introduced by nullable `int?` properties.
 */
private predicate intLiteralValue(Expr e, string v) {
  v = e.(Literal).getValue() and e.getType() instanceof IntType
  or
  intLiteralValue(e.(CastExpr).getExpr(), v)
}

predicate isKeySizeDetection(Expr call, string algo) {
  exists(Assignment a, string size |
    a = call and
    a.getLeftOperand().(PropertyAccess).getTarget().getName() = ["KeySize", "KeySizeInBits"] and
    a.getLeftOperand().(PropertyAccess).getQualifier().getType().(ValueOrRefType).getName() =
      ["CreateRsaKeyOptions", "CreateOctKeyOptions", "CreateKeyOptions", "CertificatePolicy"] and
    intLiteralValue(a.getRightOperand(), size) and
    algo = "akvault-keysize-" + size
  )
  or
  exists(MemberInitializer mi, ObjectCreation oc, string size |
    mi = call and
    oc = mi.getParent().getParent() and
    oc.getType().getName() =
      ["CreateRsaKeyOptions", "CreateOctKeyOptions", "CreateKeyOptions", "CertificatePolicy"] and
    mi.getLeftOperand().(PropertyAccess).getTarget().getName() = ["KeySize", "KeySizeInBits"] and
    intLiteralValue(mi.getRightOperand(), size) and
    algo = "akvault-keysize-" + size
  )
}

// ---------------------------------------------------------------------------
// Legacy Microsoft.Azure.KeyVault SDK (pre-Azure.* track 2)
// ---------------------------------------------------------------------------
predicate isLegacySdkDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "KeyVaultClient" and
    algo = "akvault-legacy-client"
  )

  or

  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getDeclaringType().getName() = ["KeyVaultClient", "KeyVaultClientExtensions"]
  |
    mc.getTarget().getName().matches("Encrypt%")   and algo = "akvault-encrypt"    or
    mc.getTarget().getName().matches("Decrypt%")   and algo = "akvault-decrypt"    or
    mc.getTarget().getName().matches("Sign%")      and algo = "akvault-sign"       or
    mc.getTarget().getName().matches("Verify%")    and algo = "akvault-verify"     or
    mc.getTarget().getName().matches("WrapKey%")   and algo = "akvault-wrap-key"   or
    mc.getTarget().getName().matches("UnwrapKey%") and algo = "akvault-unwrap-key" or
    mc.getTarget().getName().matches("CreateKey%") and algo = "akvault-create-key" or
    mc.getTarget().getName().matches("ImportKey%") and algo = "akvault-import-key" or
    mc.getTarget().getName().matches("GetSecret%") and algo = "akvault-get-secret" or
    mc.getTarget().getName().matches("SetSecret%") and algo = "akvault-set-secret"
  )

  or

  // JsonWebKeyEncryptionAlgorithm / JsonWebKeySignatureAlgorithm constants
  exists(FieldAccess fa |
    fa instanceof AssignableRead and
    fa = call and
    fa.getTarget().getDeclaringType().getName() = [
      "JsonWebKeyEncryptionAlgorithm", "JsonWebKeySignatureAlgorithm",
      "JsonWebKeyType", "JsonWebKeyCurveName"
    ] and
    algo = "akvault:" + fa.getTarget().getName().toLowerCase()
  )
}

// =============================================================================
// Main query
// =============================================================================

from Expr call, string algo, string api
where
  api = "Azure.Security.KeyVault" and
  (
    isClientCreationDetection(call, algo) or
    isCryptoOperationDetection(call, algo) or
    isSignVerifyDetection(call, algo) or
    isKeyWrapDetection(call, algo) or
    isKeyManagementDetection(call, algo) or
    isKeyOptionsDetection(call, algo) or
    isEncryptionAlgorithmDetection(call, algo) or
    isSignatureAlgorithmDetection(call, algo) or
    isKeyWrapAlgorithmDetection(call, algo) or
    isKeyTypeDetection(call, algo) or
    isKeyCurveDetection(call, algo) or
    isCertificatePolicyDetection(call, algo) or
    isAlgorithmStringDetection(call, algo) or
    isEncryptParametersDetection(call, algo) or
    isKeySizeDetection(call, algo) or
    isLegacySdkDetection(call, algo) or
    isSecretsOperationDetection(call, algo) or
    isCertificateOperationDetection(call, algo)
  )
select call, "algo=" + algo + ", api=" + api
