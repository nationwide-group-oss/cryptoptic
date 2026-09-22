// Test suite for NCrypt.ql (System.Security.Cryptography.Cng)
// Every method exercises at least one detection path in the QL query.
// CNG types are part of the .NET 8 BCL; no additional NuGet stubs required.

using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CbomTestSuite.Csharp
{
    // =========================================================================
    // CngKey.Create() — software KSP (ephemeral)
    // Expected: rsa-keygen, ecdsa-p256-keygen, ecdh-p384-keygen, cng-key-create
    // =========================================================================
    public static class CngKeyCreateTests
    {
        // Ephemeral RSA key (algorithm resolved via data flow)
        public static CngKey CreateRsaKey()
        {
            var algo = CngAlgorithm.Rsa;
            return CngKey.Create(algo);
        }

        // Ephemeral ECDSA P-256 key (algorithm literal)
        public static CngKey CreateEcdsaP256Key()
            => CngKey.Create(CngAlgorithm.ECDsaP256);

        // Ephemeral ECDH P-384 key
        public static CngKey CreateEcdhP384Key()
            => CngKey.Create(CngAlgorithm.ECDiffieHellmanP384);

        // Named key persisted in Software KSP
        public static CngKey CreateNamedRsaKey()
        {
            var creationParams = new CngKeyCreationParameters
            {
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                ExportPolicy = CngExportPolicies.None,
            };
            return CngKey.Create(CngAlgorithm.Rsa, "my-rsa-2048", creationParams);
        }

        // Named key persisted in TPM (Platform Crypto Provider)
        public static CngKey CreateTpmEcdsaKey()
        {
            var creationParams = new CngKeyCreationParameters
            {
                Provider = CngProvider.MicrosoftPlatformCryptoProvider,
            };
            return CngKey.Create(CngAlgorithm.ECDsaP256, "tpm-ecdsa-key", creationParams);
        }

        // Algorithm not statically resolvable — fallback cng-key-create
        public static CngKey CreateKeyUnknownAlgo(CngAlgorithm algorithm)
            => CngKey.Create(algorithm);
    }

    // =========================================================================
    // CngKey.Open() — open persisted keys from a KSP
    // Expected: cng-key-open
    // =========================================================================
    public static class CngKeyOpenTests
    {
        public static CngKey OpenFromDefaultKsp(string keyName)
            => CngKey.Open(keyName);

        public static CngKey OpenFromSoftwareKsp(string keyName)
            => CngKey.Open(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);

        public static CngKey OpenFromSmartCard(string keyName)
            => CngKey.Open(keyName, CngProvider.MicrosoftSmartCardKeyStorageProvider);

        public static CngKey OpenFromTpm(string keyName)
            => CngKey.Open(keyName, CngProvider.MicrosoftPlatformCryptoProvider);
    }

    // =========================================================================
    // CngKey.Import() — import raw key material into a KSP
    // Expected: cng-key-import
    // =========================================================================
    public static class CngKeyImportTests
    {
        public static CngKey ImportPublicKey(byte[] keyBlob)
            => CngKey.Import(keyBlob, CngKeyBlobFormat.GenericPublicBlob);

        public static CngKey ImportPrivateKey(byte[] keyBlob)
            => CngKey.Import(keyBlob, CngKeyBlobFormat.Pkcs8PrivateBlob);

        public static CngKey ImportEccPublicKey(byte[] keyBlob)
            => CngKey.Import(keyBlob, CngKeyBlobFormat.EccPublicBlob);

        public static CngKey ImportIntoProvider(byte[] keyBlob, CngProvider provider)
            => CngKey.Import(keyBlob, CngKeyBlobFormat.GenericPublicBlob, provider);
    }

    // =========================================================================
    // CngKey.Export() — export key material from a CNG key
    // Expected: cng-key-export
    // =========================================================================
    public static class CngKeyExportTests
    {
        public static byte[] ExportPublic(CngKey key)
            => key.Export(CngKeyBlobFormat.GenericPublicBlob);

        public static byte[] ExportEccPublic(CngKey key)
            => key.Export(CngKeyBlobFormat.EccPublicBlob);

        public static byte[] ExportPrivate(CngKey key)
            => key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
    }

    // =========================================================================
    // CngKey.Delete() — delete a persisted key from the KSP
    // Expected: cng-key-delete
    // =========================================================================
    public static class CngKeyDeleteTests
    {
        public static void DeleteKey(CngKey key)
            => key.Delete();
    }

    // =========================================================================
    // CNG-backed algorithm type constructors
    // Expected: rsa-keygen, ecdsa-keygen, ecdh-keygen, aes, 3des
    // =========================================================================
    public static class CngAlgorithmTypeTests
    {
        // RSACng — RSA via Windows CNG
        public static RSACng CreateRsaCng()             => new RSACng();
        public static RSACng CreateRsaCngWithSize()     => new RSACng(2048);
        public static RSACng CreateRsaCngFromKey(CngKey key) => new RSACng(key);

        // ECDsaCng — ECDSA via Windows CNG
        public static ECDsaCng CreateEcdsaCng()             => new ECDsaCng();
        public static ECDsaCng CreateEcdsaCngWithSize()     => new ECDsaCng(256);
        public static ECDsaCng CreateEcdsaCngFromKey(CngKey key) => new ECDsaCng(key);

        // ECDiffieHellmanCng — ECDH via Windows CNG
        public static ECDiffieHellmanCng CreateEcdhCng()             => new ECDiffieHellmanCng();
        public static ECDiffieHellmanCng CreateEcdhCngWithSize()     => new ECDiffieHellmanCng(256);
        public static ECDiffieHellmanCng CreateEcdhCngFromKey(CngKey key) => new ECDiffieHellmanCng(key);

        // AesCng — AES via Windows CNG (Windows-only)
        public static AesCng CreateAesCng() => new AesCng();

        // TripleDESCng — 3DES via Windows CNG (Windows-only)
        public static TripleDESCng CreateTripleDesCng() => new TripleDESCng();
    }

    // =========================================================================
    // CngAlgorithm property reads
    // Expected: cng-algo-rsa, cng-algo-ecdsa-p256, cng-algo-ecdh-p384,
    //           cng-algo-sha256, etc.
    // Note: CngAlgorithm has no Aes/TripleDes/Dh static properties in any .NET
    // version — those are only reachable via the string constructor (see
    // CngStringIdentifierTests below).
    // =========================================================================
    public static class CngAlgorithmPropertyTests
    {
        public static CngAlgorithm GetRsaAlgo()           => CngAlgorithm.Rsa;
        public static CngAlgorithm GetEcdsaAlgo()         => CngAlgorithm.ECDsa;
        public static CngAlgorithm GetEcdsaP256Algo()     => CngAlgorithm.ECDsaP256;
        public static CngAlgorithm GetEcdsaP384Algo()     => CngAlgorithm.ECDsaP384;
        public static CngAlgorithm GetEcdsaP521Algo()     => CngAlgorithm.ECDsaP521;
        public static CngAlgorithm GetEcdhAlgo()          => CngAlgorithm.ECDiffieHellman;
        public static CngAlgorithm GetEcdhP256Algo()      => CngAlgorithm.ECDiffieHellmanP256;
        public static CngAlgorithm GetEcdhP384Algo()      => CngAlgorithm.ECDiffieHellmanP384;
        public static CngAlgorithm GetEcdhP521Algo()      => CngAlgorithm.ECDiffieHellmanP521;
        public static CngAlgorithm GetMd5Algo()           => CngAlgorithm.MD5;
        public static CngAlgorithm GetSha1Algo()          => CngAlgorithm.Sha1;
        public static CngAlgorithm GetSha256Algo()        => CngAlgorithm.Sha256;
        public static CngAlgorithm GetSha384Algo()        => CngAlgorithm.Sha384;
        public static CngAlgorithm GetSha512Algo()        => CngAlgorithm.Sha512;
    }

    // =========================================================================
    // CngProvider property reads
    // Expected: cng-provider-software, cng-provider-smartcard, cng-provider-tpm
    // =========================================================================
    public static class CngProviderPropertyTests
    {
        public static CngProvider GetSoftwareKsp()      => CngProvider.MicrosoftSoftwareKeyStorageProvider;
        public static CngProvider GetSmartCardKsp()     => CngProvider.MicrosoftSmartCardKeyStorageProvider;
        public static CngProvider GetTpmProvider()      => CngProvider.MicrosoftPlatformCryptoProvider;
    }

    // =========================================================================
    // CngAlgorithm / CngProvider / CngKeyBlobFormat built from provider strings
    // Expected algo tags: cng-algo:ecdsa_p256, cng-algo:rsa,
    //                     cng-provider:microsoft software key storage provider,
    //                     cng-blob:eccpublicblob
    // =========================================================================
    public static class CngStringIdentifierTests
    {
        public static CngAlgorithm EcdsaP256FromString() => new CngAlgorithm("ECDSA_P256");
        public static CngAlgorithm RsaFromString()       => new CngAlgorithm("RSA");
        public static CngAlgorithm AesGcmFromString()     => new CngAlgorithm("AES");
        public static CngProvider ProviderFromString()    => new CngProvider("Microsoft Software Key Storage Provider");
        public static CngKeyBlobFormat BlobFromString()   => new CngKeyBlobFormat("ECCPUBLICBLOB");

        // No CngAlgorithm.Aes/TripleDes/Dh convenience properties exist in the BCL;
        // BCRYPT_3DES_ALGORITHM / BCRYPT_DH_ALGORITHM are only reachable as raw strings.
        public static CngAlgorithm TripleDesFromString()  => new CngAlgorithm("3DES");
        public static CngAlgorithm DhFromString()         => new CngAlgorithm("DH");

        // ML-DSA / ML-KEM / SLH-DSA (.NET 10+ CngAlgorithm properties) via raw
        // BCRYPT_*_ALGORITHM string, matched by isCngAlgorithmStringDetection.
        public static CngAlgorithm MlDsaFromString()      => new CngAlgorithm("ML-DSA");
        public static CngAlgorithm MlKemFromString()      => new CngAlgorithm("ML-KEM");
        public static CngAlgorithm SlhDsaFromString()     => new CngAlgorithm("SLH-DSA");
    }

    // =========================================================================
    // Explicit CNG key length via CngKeyCreationParameters / CngProperty
    // Expected algo tags: cng-key-params, cng-property:length
    // =========================================================================
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static class CngKeyLengthTests
    {
        public static CngKey CreateRsa4096()
        {
            var parameters = new CngKeyCreationParameters
            {
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider
            };
            parameters.Parameters.Add(
                new CngProperty("Length", System.BitConverter.GetBytes(4096), CngPropertyOptions.None));
            return CngKey.Create(CngAlgorithm.Rsa, "rsa-4096-key", parameters);
        }
    }

    // =========================================================================
    // Raw NCrypt / BCrypt P/Invoke interop
    // Expected algo tags: cng-algo:aes, cng-algo:sha256,
    //                     cng-interop:bcryptencrypt, cng-interop:bcryptgenrandom,
    //                     cng-interop:ncryptopenkey, cng-interop:ncryptsignhash
    // =========================================================================
    public static class CngInteropTests
    {
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(
            out System.IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptGenerateSymmetricKey(
            System.IntPtr hAlgorithm, out System.IntPtr phKey, System.IntPtr pbKeyObject,
            uint cbKeyObject, byte[] pbSecret, uint cbSecret, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptEncrypt(
            System.IntPtr hKey, byte[] pbInput, uint cbInput, System.IntPtr pPaddingInfo,
            byte[] pbIV, uint cbIV, byte[] pbOutput, uint cbOutput, out uint pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptGenRandom(
            System.IntPtr hAlgorithm, byte[] pbBuffer, uint cbBuffer, uint dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptOpenStorageProvider(
            out System.IntPtr phProvider, string pszProviderName, uint dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptCreatePersistedKey(
            System.IntPtr hProvider, out System.IntPtr phKey, string pszAlgId,
            string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptOpenKey(
            System.IntPtr hProvider, out System.IntPtr phKey, string pszKeyName,
            uint dwLegacyKeySpec, uint dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptSignHash(
            System.IntPtr hKey, System.IntPtr pPaddingInfo, byte[] pbHashValue, uint cbHashValue,
            byte[] pbSignature, uint cbSignature, out uint pcbResult, uint dwFlags);

        public static System.IntPtr OpenAesProvider()
        {
            BCryptOpenAlgorithmProvider(out var handle, "AES", null, 0);
            return handle;
        }

        public static System.IntPtr OpenSha256Provider()
        {
            BCryptOpenAlgorithmProvider(out var handle, "SHA256", null, 0);
            return handle;
        }

        public static void EncryptWithBCrypt(System.IntPtr key, byte[] data, byte[] iv, byte[] output)
        {
            BCryptGenerateSymmetricKey(key, out var hKey, System.IntPtr.Zero, 0, data, (uint)data.Length, 0);
            BCryptEncrypt(hKey, data, (uint)data.Length, System.IntPtr.Zero, iv, (uint)iv.Length,
                output, (uint)output.Length, out _, 0);
        }

        public static void RandomBytes(byte[] buffer) =>
            BCryptGenRandom(System.IntPtr.Zero, buffer, (uint)buffer.Length, 2);

        public static System.IntPtr CreatePersistedEcdsaKey()
        {
            NCryptOpenStorageProvider(out var provider, "Microsoft Software Key Storage Provider", 0);
            NCryptCreatePersistedKey(provider, out var key, "ECDSA_P384", "signing-key", 0, 0);
            return key;
        }

        public static System.IntPtr OpenPersistedKey(System.IntPtr provider)
        {
            NCryptOpenKey(provider, out var key, "signing-key", 0, 0);
            return key;
        }

        public static void SignWithNCrypt(System.IntPtr key, byte[] hash, byte[] signature) =>
            NCryptSignHash(key, System.IntPtr.Zero, hash, (uint)hash.Length,
                signature, (uint)signature.Length, out _, 0);
    }

    // =========================================================================
    // Remaining NCrypt interop entry point
    // Expected algo tag: cng-interop:ncryptverifysignature
    // =========================================================================
    public static class CngInteropVerifyTests
    {
        [DllImport("ncrypt.dll")]
        private static extern int NCryptVerifySignature(
            System.IntPtr hKey, System.IntPtr pPaddingInfo, byte[] pbHashValue, uint cbHashValue,
            byte[] pbSignature, uint cbSignature, uint dwFlags);

        public static bool Verify(System.IntPtr key, byte[] hash, byte[] signature) =>
            NCryptVerifySignature(key, System.IntPtr.Zero, hash, (uint)hash.Length,
                signature, (uint)signature.Length, 0) == 0;
    }

    // =========================================================================
    // Remaining CngAlgorithm identifiers
    // Expected algo tags: ecdh-p256-keygen, ecdh-p521-keygen,
    //                     ecdsa-p384-keygen, ecdsa-p521-keygen
    // =========================================================================
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static class CngRemainingAlgorithmTests
    {
        public static CngKey CreateEcdhP256()  => CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
        public static CngKey CreateEcdhP521()  => CngKey.Create(CngAlgorithm.ECDiffieHellmanP521);
        public static CngKey CreateEcdsaP384() => CngKey.Create(CngAlgorithm.ECDsaP384);
        public static CngKey CreateEcdsaP521() => CngKey.Create(CngAlgorithm.ECDsaP521);

        // ML-DSA/ML-KEM/SLH-DSA (.NET 10+ CngAlgorithm.MLDsa/.MLKem/.SlhDsa properties,
        // mapped by cngAlgoDirect/isCngAlgorithmPropertyDetection) can't be referenced
        // as property syntax under this project's net8.0 target — see
        // CngStringIdentifierTests for the equivalent string-constructor form.
    }

}
