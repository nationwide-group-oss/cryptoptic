// Test suite for AzureKeyVault.ql
// Every method exercises at least one detection path in the QL query.
// The project is not intended to compile against the real Azure SDK; type-stubs.cs
// provides declarations so the CodeQL extractor can resolve types in --build-mode=none.

using System;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;
using Azure.Security.KeyVault.Certificates;

namespace CbomTestSuite.Csharp
{
    // =========================================================================
    // Client construction
    // Expected algo tags: akvault-cryptography-client, akvault-key-client,
    //                     akvault-secret-client, akvault-certificate-client
    // =========================================================================
    public static class AkvClientCreationTests
    {
        static readonly Uri VaultUri = new Uri("https://my-vault.vault.azure.net");
        static readonly TokenCredential Credential = null;

        public static CryptographyClient MakeCryptoClient(Uri keyId)
            => new CryptographyClient(keyId, Credential);

        public static KeyClient MakeKeyClient()
            => new KeyClient(VaultUri, Credential);

        public static SecretClient MakeSecretClient()
            => new SecretClient(VaultUri, Credential);

        public static CertificateClient MakeCertificateClient()
            => new CertificateClient(VaultUri, Credential);
    }

    // =========================================================================
    // Encrypt / Decrypt (CryptographyClient)
    // Expected algo tags: akvault-encrypt, akvault-decrypt
    // =========================================================================
    public static class AkvEncryptionTests
    {
        static CryptographyClient Client => null;

        public static EncryptResult EncryptRsaOaep256(byte[] plaintext)
            => Client.Encrypt(EncryptionAlgorithm.RsaOaep256, plaintext);

        public static DecryptResult DecryptRsaOaep256(byte[] ciphertext)
            => Client.Decrypt(EncryptionAlgorithm.RsaOaep256, ciphertext);

        public static EncryptResult EncryptAes256Gcm(byte[] plaintext)
            => Client.Encrypt(EncryptionAlgorithm.A256Gcm, plaintext);

        public static DecryptResult DecryptAes256Gcm(byte[] ciphertext)
            => Client.Decrypt(EncryptionAlgorithm.A256Gcm, ciphertext);
    }

    // =========================================================================
    // EncryptionAlgorithm field accesses
    // Expected algo tags: rsa-1_5, rsa-oaep, rsa-oaep-256,
    //   aes-128-gcm, aes-192-gcm, aes-256-gcm,
    //   aes-128-cbc, aes-192-cbc, aes-256-cbc,
    //   aes-128-cbc-pad, aes-192-cbc-pad, aes-256-cbc-pad
    // =========================================================================
    public static class AkvEncryptionAlgorithmTests
    {
        public static void AllEncryptionAlgorithms()
        {
            _ = EncryptionAlgorithm.Rsa15;
            _ = EncryptionAlgorithm.RsaOaep;
            _ = EncryptionAlgorithm.RsaOaep256;
            _ = EncryptionAlgorithm.A128Gcm;
            _ = EncryptionAlgorithm.A192Gcm;
            _ = EncryptionAlgorithm.A256Gcm;
            _ = EncryptionAlgorithm.A128Cbc;
            _ = EncryptionAlgorithm.A192Cbc;
            _ = EncryptionAlgorithm.A256Cbc;
            _ = EncryptionAlgorithm.A128CbcPad;
            _ = EncryptionAlgorithm.A192CbcPad;
            _ = EncryptionAlgorithm.A256CbcPad;
        }
    }

    // =========================================================================
    // Sign / Verify (CryptographyClient)
    // Expected algo tags: akvault-sign, akvault-sign-data,
    //                     akvault-verify, akvault-verify-data
    // =========================================================================
    public static class AkvSignVerifyTests
    {
        static CryptographyClient Client => null;

        public static SignResult SignDigest(byte[] digest)
            => Client.Sign(SignatureAlgorithm.RS256, digest);

        public static SignResult SignRawData(byte[] data)
            => Client.SignData(SignatureAlgorithm.ES256, data);

        public static VerifyResult VerifyDigest(byte[] digest, byte[] signature)
            => Client.Verify(SignatureAlgorithm.RS256, digest, signature);

        public static VerifyResult VerifyRawData(byte[] data, byte[] signature)
            => Client.VerifyData(SignatureAlgorithm.ES256, data, signature);
    }

    // =========================================================================
    // SignatureAlgorithm field accesses
    // Expected algo tags: rs256, rs384, rs512, ps256, ps384, ps512,
    //                     es256, es384, es512, es256k
    // =========================================================================
    public static class AkvSignatureAlgorithmTests
    {
        public static void AllSignatureAlgorithms()
        {
            _ = SignatureAlgorithm.RS256;
            _ = SignatureAlgorithm.RS384;
            _ = SignatureAlgorithm.RS512;
            _ = SignatureAlgorithm.PS256;
            _ = SignatureAlgorithm.PS384;
            _ = SignatureAlgorithm.PS512;
            _ = SignatureAlgorithm.ES256;
            _ = SignatureAlgorithm.ES384;
            _ = SignatureAlgorithm.ES512;
            _ = SignatureAlgorithm.ES256K;
        }
    }

    // =========================================================================
    // Key wrap / unwrap (CryptographyClient)
    // Expected algo tags: akvault-wrap-key, akvault-unwrap-key
    // =========================================================================
    public static class AkvKeyWrapTests
    {
        static CryptographyClient Client => null;

        public static WrapResult WrapAes256(byte[] key)
            => Client.WrapKey(KeyWrapAlgorithm.A256KW, key);

        public static UnwrapResult UnwrapAes256(byte[] wrappedKey)
            => Client.UnwrapKey(KeyWrapAlgorithm.A256KW, wrappedKey);

        public static WrapResult WrapRsaOaep256(byte[] key)
            => Client.WrapKey(KeyWrapAlgorithm.RsaOaep256, key);

        public static UnwrapResult UnwrapRsaOaep256(byte[] wrappedKey)
            => Client.UnwrapKey(KeyWrapAlgorithm.RsaOaep256, wrappedKey);
    }

    // =========================================================================
    // KeyWrapAlgorithm field accesses
    // Expected algo tags: rsa-1_5-wrap, rsa-oaep-wrap, rsa-oaep-256-wrap,
    //                     aes-128-kw, aes-192-kw, aes-256-kw
    // =========================================================================
    public static class AkvKeyWrapAlgorithmTests
    {
        public static void AllKeyWrapAlgorithms()
        {
            _ = KeyWrapAlgorithm.Rsa15;
            _ = KeyWrapAlgorithm.RsaOaep;
            _ = KeyWrapAlgorithm.RsaOaep256;
            _ = KeyWrapAlgorithm.A128KW;
            _ = KeyWrapAlgorithm.A192KW;
            _ = KeyWrapAlgorithm.A256KW;
        }
    }

    // =========================================================================
    // Key lifecycle management (KeyClient)
    // Expected algo tags: akvault-create-key, akvault-create-rsa-key,
    //   akvault-create-ec-key, akvault-create-oct-key, akvault-import-key,
    //   akvault-rotate-key, akvault-get-key, akvault-delete-key,
    //   akvault-update-key, akvault-backup-key, akvault-restore-key,
    //   akvault-recover-key, akvault-purge-key,
    //   akvault-get-rotation-policy, akvault-update-rotation-policy
    // =========================================================================
    public static class AkvKeyManagementTests
    {
        static KeyClient Client => null;

        public static KeyVaultKey CreateGeneric()
            => Client.CreateKey("my-key", KeyType.Rsa).Value;

        public static KeyVaultKey CreateRsa()
            => Client.CreateRsaKey(new CreateRsaKeyOptions("my-rsa-key") { KeySize = 4096 }).Value;

        public static KeyVaultKey CreateEc()
            => Client.CreateEcKey(new CreateEcKeyOptions("my-ec-key")).Value;

        public static KeyVaultKey CreateOct()
            => Client.CreateOctKey(new CreateOctKeyOptions("my-oct-key")).Value;

        public static KeyVaultKey ImportKey(ImportKeyOptions options)
            => Client.ImportKey(options).Value;

        public static KeyVaultKey RotateKey()
            => Client.RotateKey("my-key").Value;

        public static KeyVaultKey GetKey()
            => Client.GetKey("my-key").Value;

        public static DeleteKeyOperation DeleteKey()
            => Client.DeleteKey("my-key");

        public static void UpdateKey(KeyVaultKey key)
            => Client.UpdateKeyProperties(key.Properties);

        public static byte[] BackupKey()
            => Client.BackupKey("my-key").Value;

        public static KeyVaultKey RestoreKey(byte[] backup)
            => Client.RestoreKeyBackup(backup).Value;

        public static RecoverDeletedKeyOperation RecoverKey()
            => Client.RecoverDeletedKey("my-key");

        public static void PurgeKey()
            => Client.PurgeDeletedKey("my-key");

        public static KeyRotationPolicy GetRotationPolicy()
            => Client.GetKeyRotationPolicy("my-key").Value;

        public static KeyRotationPolicy UpdateRotationPolicy(KeyRotationPolicy policy)
            => Client.UpdateKeyRotationPolicy("my-key", policy).Value;
    }

    // =========================================================================
    // KeyType field accesses
    // Expected algo tags: rsa, rsa-hsm, ec, ec-hsm, aes, aes-hsm
    // =========================================================================
    public static class AkvKeyTypeTests
    {
        public static void AllKeyTypes()
        {
            _ = KeyType.Rsa;
            _ = KeyType.RsaHsm;
            _ = KeyType.Ec;
            _ = KeyType.EcHsm;
            _ = KeyType.Oct;
            _ = KeyType.OctHsm;
        }
    }

    // =========================================================================
    // Key creation options construction
    // Expected algo tags: akvault-rsa-key-options, akvault-ec-key-options,
    //                     akvault-oct-key-options, akvault-import-key-options
    // =========================================================================
    public static class AkvKeyOptionsTests
    {
        public static CreateRsaKeyOptions RsaOptions()
            => new CreateRsaKeyOptions("my-rsa-key") { KeySize = 2048 };

        public static CreateEcKeyOptions EcOptions()
            => new CreateEcKeyOptions("my-ec-key");

        public static CreateOctKeyOptions OctOptions()
            => new CreateOctKeyOptions("my-oct-key") { KeySize = 256 };

        public static ImportKeyOptions ImportOptions(JsonWebKey jwk)
            => new ImportKeyOptions("my-key", jwk);
    }

    // =========================================================================
    // Secrets operations (SecretClient)
    // Expected algo tags: akvault-get-secret, akvault-set-secret,
    //                     akvault-delete-secret
    // =========================================================================
    public static class AkvSecretsTests
    {
        static SecretClient Client => null;

        public static KeyVaultSecret GetSecret()
            => Client.GetSecret("my-secret").Value;

        public static KeyVaultSecret SetSecret()
            => Client.SetSecret("my-secret", "super-secret-value").Value;

        public static DeleteSecretOperation DeleteSecret()
            => Client.DeleteSecret("my-secret");
    }

    // =========================================================================
    // Certificate operations (CertificateClient)
    // Expected algo tags: akvault-create-certificate, akvault-get-certificate,
    //                     akvault-import-certificate
    // =========================================================================
    public static class AkvCertificatesTests
    {
        static CertificateClient Client => null;

        public static CertificateOperation CreateCertificate()
            => Client.StartCreateCertificate("my-cert", CertificatePolicy.Default);

        public static KeyVaultCertificateWithPolicy GetCertificate()
            => Client.GetCertificate("my-cert").Value;

        public static KeyVaultCertificateWithPolicy ImportCertificate(ImportCertificateOptions options)
            => Client.ImportCertificate(options).Value;
    }

    // =========================================================================
    // Key curves, key sizes and string-constructed algorithm identifiers
    // Expected algo tags: ec-p256, ec-p384, ec-p521, ec-secp256k1,
    //                     akvault-keysize-3072, akvault:rsa-oaep-256
    // =========================================================================
    public static class AkvAlgorithmIdentifierTests
    {
        public static KeyCurveName P256()  => KeyCurveName.P256;
        public static KeyCurveName P384()  => KeyCurveName.P384;
        public static KeyCurveName P521()  => KeyCurveName.P521;
        public static KeyCurveName P256K() => KeyCurveName.P256K;

        public static CreateRsaKeyOptions Rsa3072Options() =>
            new CreateRsaKeyOptions("rsa-key") { KeySize = 3072 };

        public static CreateOctKeyOptions Aes256Options()
        {
            var options = new CreateOctKeyOptions("oct-key");
            options.KeySize = 256;
            return options;
        }

        public static EncryptionAlgorithm FromString()      => new EncryptionAlgorithm("RSA-OAEP-256");
        public static SignatureAlgorithm SigFromString()    => new SignatureAlgorithm("PS512");
        public static KeyWrapAlgorithm WrapFromString()     => new KeyWrapAlgorithm("A256KW");
        public static KeyCurveName CurveFromString()        => new KeyCurveName("P-256K");
    }

    // =========================================================================
    // EncryptParameters / DecryptParameters factories
    // Expected algo tags: aes-256-gcm, aes-256-cbc-pad, rsa-oaep-256, rsa-1_5
    // =========================================================================
    public static class AkvEncryptParametersTests
    {
        public static EncryptParameters Aes256Gcm(byte[] plaintext, byte[] iv, byte[] aad) =>
            EncryptParameters.A256GcmParameters(plaintext, iv, aad);

        public static EncryptParameters Aes256CbcPad(byte[] plaintext, byte[] iv) =>
            EncryptParameters.A256CbcPadParameters(plaintext, iv);

        public static EncryptParameters RsaOaep256(byte[] plaintext) =>
            EncryptParameters.RsaOaep256Parameters(plaintext);

        public static EncryptParameters Rsa15(byte[] plaintext) =>
            EncryptParameters.Rsa15Parameters(plaintext);

        public static DecryptParameters DecryptAes256Gcm(byte[] ciphertext, byte[] iv, byte[] tag) =>
            DecryptParameters.A256GcmParameters(ciphertext, iv, tag);
    }

    // =========================================================================
    // Legacy Microsoft.Azure.KeyVault (track 1) SDK
    // Expected algo tags: akvault-legacy-client, akvault-encrypt, akvault-sign,
    //                     akvault-wrap-key, akvault:rsaoaep256
    // =========================================================================
    public static class AkvLegacySdkTests
    {
        private static readonly Microsoft.Azure.KeyVault.KeyVaultClient Legacy =
            new Microsoft.Azure.KeyVault.KeyVaultClient(null);

        public static object LegacyEncrypt(string keyId, byte[] data) =>
            Legacy.EncryptAsync(keyId, Microsoft.Azure.KeyVault.WebKey.JsonWebKeyEncryptionAlgorithm.RSAOAEP256, data);

        public static object LegacyDecrypt(string keyId, byte[] data) =>
            Legacy.DecryptAsync(keyId, Microsoft.Azure.KeyVault.WebKey.JsonWebKeyEncryptionAlgorithm.RSAOAEP, data);

        public static object LegacySign(string keyId, byte[] digest) =>
            Legacy.SignAsync(keyId, Microsoft.Azure.KeyVault.WebKey.JsonWebKeySignatureAlgorithm.RS256, digest);

        public static object LegacyWrap(string keyId, byte[] key) =>
            Legacy.WrapKeyAsync(keyId, Microsoft.Azure.KeyVault.WebKey.JsonWebKeyEncryptionAlgorithm.RSA15, key);
    }

    // =========================================================================
    // Remaining EncryptParameters factories
    // Expected algo tags: rsa-oaep, aes-128-gcm, aes-192-gcm, aes-128-cbc,
    //                     aes-192-cbc, aes-256-cbc, aes-128-cbc-pad, aes-192-cbc-pad
    // =========================================================================
    public static class AkvRemainingParametersTests
    {
        public static EncryptParameters RsaOaep(byte[] p)     => EncryptParameters.RsaOaepParameters(p);
        public static EncryptParameters Aes128Gcm(byte[] p)   => EncryptParameters.A128GcmParameters(p);
        public static EncryptParameters Aes192Gcm(byte[] p)   => EncryptParameters.A192GcmParameters(p);
        public static EncryptParameters Aes128Cbc(byte[] p)   => EncryptParameters.A128CbcParameters(p);
        public static EncryptParameters Aes192Cbc(byte[] p)   => EncryptParameters.A192CbcParameters(p);
        public static EncryptParameters Aes256Cbc(byte[] p)   => EncryptParameters.A256CbcParameters(p);
        public static EncryptParameters Aes128CbcPad(byte[] p) => EncryptParameters.A128CbcPadParameters(p);
        public static EncryptParameters Aes192CbcPad(byte[] p) => EncryptParameters.A192CbcPadParameters(p);

        public static DecryptParameters DecryptRsaOaep(byte[] c) => DecryptParameters.RsaOaepParameters(c);
        public static DecryptParameters DecryptRsa15(byte[] c)   => DecryptParameters.Rsa15Parameters(c);
    }

    // =========================================================================
    // KeyClient CSPRNG and secure key release
    // Expected algo tags: akvault-csprng, akvault-release-key
    // =========================================================================
    public static class AkvKeyRandomAndReleaseTests
    {
        static KeyClient Client => null;

        public static byte[] RandomBytes() => Client.GetRandomBytes(32).Value;

        public static byte[] ReleaseKey() => Client.ReleaseKey("my-key", "attestation-target").Value;
    }

    // =========================================================================
    // Additional SecretClient lifecycle operations
    // Expected algo tags: akvault-update-secret, akvault-backup-secret,
    //   akvault-restore-secret, akvault-recover-secret, akvault-purge-secret,
    //   akvault-get-deleted-secret
    // =========================================================================
    public static class AkvSecretLifecycleTests
    {
        static SecretClient Client => null;

        public static void UpdateSecret(SecretProperties properties)
            => Client.UpdateSecretProperties(properties);

        public static byte[] BackupSecret() => Client.BackupSecret("my-secret").Value;

        public static KeyVaultSecret RestoreSecret(byte[] backup) => Client.RestoreSecretBackup(backup).Value;

        public static RecoverDeletedSecretOperation RecoverSecret() => Client.RecoverDeletedSecret("my-secret");

        public static void PurgeSecret() => Client.PurgeDeletedSecret("my-secret");

        public static DeletedSecret GetDeletedSecret() => Client.GetDeletedSecret("my-secret").Value;
    }

    // =========================================================================
    // Additional CertificateClient lifecycle and policy operations
    // Expected algo tags: akvault-merge-certificate, akvault-get-certificate-policy,
    //   akvault-update-certificate-policy, akvault-backup-certificate,
    //   akvault-restore-certificate, akvault-delete-certificate,
    //   akvault-recover-certificate, akvault-purge-certificate,
    //   akvault-get-certificate-operation, akvault-cancel-certificate-operation
    // =========================================================================
    public static class AkvCertificateLifecycleTests
    {
        static CertificateClient Client => null;

        public static KeyVaultCertificateWithPolicy MergeCertificate(MergeCertificateOptions options)
            => Client.MergeCertificate(options).Value;

        public static CertificatePolicy GetPolicy() => Client.GetCertificatePolicy("my-cert").Value;

        public static CertificatePolicy UpdatePolicy(CertificatePolicy policy)
            => Client.UpdateCertificatePolicy("my-cert", policy).Value;

        public static byte[] BackupCertificate() => Client.BackupCertificate("my-cert").Value;

        public static KeyVaultCertificateWithPolicy RestoreCertificate(byte[] backup)
            => Client.RestoreCertificateBackup(backup).Value;

        public static DeleteCertificateOperation DeleteCertificate() => Client.StartDeleteCertificate("my-cert");

        public static RecoverDeletedCertificateOperation RecoverCertificate() =>
            Client.StartRecoverDeletedCertificate("my-cert");

        public static void PurgeCertificate() => Client.PurgeDeletedCertificate("my-cert");

        public static CertificateOperation GetOperation() => Client.GetCertificateOperation("my-cert");

        public static CertificateOperation CancelOperation() => Client.CancelCertificateOperation("my-cert");
    }

    // =========================================================================
    // Certificate policy — the key algorithm underlying a Key Vault certificate
    // Expected algo tags: akvault-certificate-policy, rsa-hsm, ec-secp256k1,
    //   pkcs12, akvault-keysize-3072
    // =========================================================================
    public static class AkvCertificatePolicyTests
    {
        public static CertificatePolicy NewPolicy() => new CertificatePolicy("Self", "CN=example.com");

        public static CertificatePolicy RsaHsmPolicy() => new CertificatePolicy("Self", "CN=example.com")
        {
            KeyType = CertificateKeyType.RsaHsm,
            KeySize = 3072
        };

        public static CertificatePolicy EcPolicy() => new CertificatePolicy("Self", "CN=example.com")
        {
            KeyType = CertificateKeyType.Ec,
            KeyCurveName = CertificateKeyCurveName.P256K
        };

        public static CertificatePolicy Pkcs12Policy() => new CertificatePolicy("Self", "CN=example.com")
        {
            ContentType = CertificateContentType.Pkcs12
        };

        public static CertificatePolicy PemPolicy() => new CertificatePolicy("Self", "CN=example.com")
        {
            ContentType = CertificateContentType.Pem
        };
    }

}
