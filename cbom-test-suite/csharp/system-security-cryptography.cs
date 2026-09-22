using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace CbomTestSuite.Csharp
{
    // =========================================================================
    // Hashing
    // Covers: SHA1, SHA256, SHA384, SHA512, SHA3-256/384/512, MD5, SHAKE128/256
    // via Create() factories, HashData() one-shots, legacy Managed/CSP constructors.
    // Expected algo tags: sha1, sha256, sha384, sha512, sha3-256, sha3-384,
    //                     sha3-512, md5, shake-128, shake-256
    // =========================================================================
    public static class HashingTests
    {
        private static readonly byte[] Data = new byte[64];

        public static byte[] Sha256ViaCreate()
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha256HashData() => SHA256.HashData(Data);

        public static byte[] Sha256ManagedLegacy()
        {
#pragma warning disable SYSLIB0021
            using var sha = new SHA256Managed();
#pragma warning restore SYSLIB0021
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha256CspLegacy()
        {
#pragma warning disable SYSLIB0021
            using var sha = new SHA256CryptoServiceProvider();
#pragma warning restore SYSLIB0021
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha1ViaCreate()
        {
            using var sha = SHA1.Create();
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha1HashData() => SHA1.HashData(Data);

        public static byte[] Sha1ManagedLegacy()
        {
#pragma warning disable SYSLIB0021
            using var sha = new SHA1Managed();
#pragma warning restore SYSLIB0021
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha1CspLegacy()
        {
#pragma warning disable SYSLIB0021
            using var sha = new SHA1CryptoServiceProvider();
#pragma warning restore SYSLIB0021
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha384ViaCreate()
        {
            using var sha = SHA384.Create();
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha384HashData() => SHA384.HashData(Data);

        public static byte[] Sha384ManagedLegacy()
        {
#pragma warning disable SYSLIB0021
            using var sha = new SHA384Managed();
#pragma warning restore SYSLIB0021
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha384CspLegacy()
        {
#pragma warning disable SYSLIB0021
            using var sha = new SHA384CryptoServiceProvider();
#pragma warning restore SYSLIB0021
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha512ViaCreate()
        {
            using var sha = SHA512.Create();
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha512HashData() => SHA512.HashData(Data);

        public static byte[] Sha512ManagedLegacy()
        {
#pragma warning disable SYSLIB0021
            using var sha = new SHA512Managed();
#pragma warning restore SYSLIB0021
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha512CspLegacy()
        {
#pragma warning disable SYSLIB0021
            using var sha = new SHA512CryptoServiceProvider();
#pragma warning restore SYSLIB0021
            return sha.ComputeHash(Data);
        }

        public static byte[] Md5ViaCreate()
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(Data);
        }

        public static byte[] Md5HashData() => MD5.HashData(Data);

        public static byte[] Md5CspLegacy()
        {
#pragma warning disable SYSLIB0021
            using var md5 = new MD5CryptoServiceProvider();
#pragma warning restore SYSLIB0021
            return md5.ComputeHash(Data);
        }

        // SHA3 / SHAKE (.NET 8+)
        public static byte[] Sha3_256ViaCreate()
        {
            using var sha = SHA3_256.Create();
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha3_256HashData() => SHA3_256.HashData(Data);

        public static byte[] Sha3_384ViaCreate()
        {
            using var sha = SHA3_384.Create();
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha3_384HashData() => SHA3_384.HashData(Data);

        public static byte[] Sha3_512ViaCreate()
        {
            using var sha = SHA3_512.Create();
            return sha.ComputeHash(Data);
        }

        public static byte[] Sha3_512HashData() => SHA3_512.HashData(Data);

        public static byte[] Shake128ViaConstructor()
        {
            using var shake = new Shake128();
            shake.AppendData(Data);
            return shake.GetCurrentHash(32);
        }

        public static byte[] Shake128HashData() =>
            Shake128.HashData(Data, 32);

        public static byte[] Shake256ViaConstructor()
        {
            using var shake = new Shake256();
            shake.AppendData(Data);
            return shake.GetCurrentHash(64);
        }

        public static byte[] Shake256HashData() =>
            Shake256.HashData(Data, 64);

        public static byte[] IncrementalHashSha256()
        {
            using var inc = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            inc.AppendData(Data);
            return inc.GetHashAndReset();
        }

        public static byte[] IncrementalHashSha384()
        {
            using var inc = IncrementalHash.CreateHash(HashAlgorithmName.SHA384);
            inc.AppendData(Data);
            return inc.GetHashAndReset();
        }

        public static byte[] IncrementalHashSha1()
        {
            using var inc = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
            inc.AppendData(Data);
            return inc.GetHashAndReset();
        }

        public static byte[] IncrementalHashMd5()
        {
            using var inc = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            inc.AppendData(Data);
            return inc.GetHashAndReset();
        }

        public static byte[] IncrementalHashSha512()
        {
            using var inc = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
            inc.AppendData(Data);
            return inc.GetHashAndReset();
        }

        public static byte[]? HashAlgorithmStringFactory()
        {
#pragma warning disable SYSLIB0045
            using var sha = HashAlgorithm.Create("SHA256");
#pragma warning restore SYSLIB0045
            return sha?.ComputeHash(Data);
        }
    }

    // =========================================================================
    // HMAC
    // Covers: HMACMD5, HMACSHA1/256/384/512, HMACSHA3-256/384/512 (.NET 8+),
    //         HMAC.Create(string) factory.
    // Expected algo tags: hmac-md5, hmac-sha1, hmac-sha256, hmac-sha384,
    //                     hmac-sha512, hmac-sha3-256, hmac-sha3-384, hmac-sha3-512
    // =========================================================================
    public static class HmacTests
    {
        private static readonly byte[] Key = new byte[32];
        private static readonly byte[] Data = new byte[64];

        public static byte[] HmacSha256Constructor()
        {
            using var hmac = new HMACSHA256(Key);
            return hmac.ComputeHash(Data);
        }

        public static byte[] HmacSha256HashData() => HMACSHA256.HashData(Key, Data);

        public static byte[] HmacSha1Constructor()
        {
            using var hmac = new HMACSHA1(Key);
            return hmac.ComputeHash(Data);
        }

        public static byte[] HmacSha1HashData() => HMACSHA1.HashData(Key, Data);

        public static byte[] HmacSha384Constructor()
        {
            using var hmac = new HMACSHA384(Key);
            return hmac.ComputeHash(Data);
        }

        public static byte[] HmacSha384HashData() => HMACSHA384.HashData(Key, Data);

        public static byte[] HmacSha512Constructor()
        {
            using var hmac = new HMACSHA512(Key);
            return hmac.ComputeHash(Data);
        }

        public static byte[] HmacSha512HashData() => HMACSHA512.HashData(Key, Data);

        public static byte[] HmacMd5Constructor()
        {
            using var hmac = new HMACMD5(Key);
            return hmac.ComputeHash(Data);
        }

        public static byte[] HmacMd5HashData() => HMACMD5.HashData(Key, Data);

        public static byte[] IncrementalHmacSha256()
        {
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, Key);
            hmac.AppendData(Data);
            return hmac.GetHashAndReset();
        }

        public static byte[] IncrementalHmacSha512()
        {
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA512, Key);
            hmac.AppendData(Data);
            return hmac.GetHashAndReset();
        }

        // HMACSHA3 (.NET 8+)
        public static byte[] HmacSha3_256Constructor()
        {
            using var hmac = new HMACSHA3_256(Key);
            return hmac.ComputeHash(Data);
        }

        public static byte[] HmacSha3_256HashData() => HMACSHA3_256.HashData(Key, Data);

        public static byte[] HmacSha3_384Constructor()
        {
            using var hmac = new HMACSHA3_384(Key);
            return hmac.ComputeHash(Data);
        }

        public static byte[] HmacSha3_384HashData() => HMACSHA3_384.HashData(Key, Data);

        public static byte[] HmacSha3_512Constructor()
        {
            using var hmac = new HMACSHA3_512(Key);
            return hmac.ComputeHash(Data);
        }

        public static byte[] HmacSha3_512HashData() => HMACSHA3_512.HashData(Key, Data);

        public static byte[]? HmacStringFactory()
        {
#pragma warning disable SYSLIB0045
            using var hmac = HMAC.Create("HMACSHA256");
#pragma warning restore SYSLIB0045
            return hmac?.ComputeHash(Data);
        }
    }

    // =========================================================================
    // Symmetric Encryption
    // Covers: AES (Create / CSP / Managed), AES-GCM, AES-CCM,
    //         ChaCha20-Poly1305 (.NET 8+), TripleDES, DES, RC2,
    //         SymmetricAlgorithm.Create(string) factory.
    // Expected algo tags: aes, aes-gcm, aes-ccm, chacha20-poly1305,
    //                     3des, des, rc2
    // =========================================================================
    public static class SymmetricTests
    {
        private static readonly byte[] Key24 = new byte[24];
        private static readonly byte[] Key32 = new byte[32];
        private static readonly byte[] Iv16  = new byte[16];
        private static readonly byte[] Data  = new byte[64];

        public static ICryptoTransform AesViaCreate()
        {
            using var aes = Aes.Create();
            aes.Key = Key32;
            aes.IV  = Iv16;
            return aes.CreateEncryptor();
        }

        public static ICryptoTransform AesCbcCreate()
        {
            using var aes = Aes.Create();
            aes.Mode    = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key     = Key32;
            aes.IV      = Iv16;
            return aes.CreateEncryptor();
        }

        public static ICryptoTransform AesEcbCreate()
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Key  = Key32;
            return aes.CreateEncryptor();
        }

        public static ICryptoTransform AesCfbCreate()
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CFB;
            aes.Key  = Key32;
            aes.IV   = Iv16;
            return aes.CreateEncryptor();
        }

        public static ICryptoTransform AesCspLegacy()
        {
#pragma warning disable SYSLIB0021
            using var aes = new AesCryptoServiceProvider();
#pragma warning restore SYSLIB0021
            aes.Key = Key32;
            aes.IV  = Iv16;
            return aes.CreateEncryptor();
        }

        public static ICryptoTransform AesManagedLegacy()
        {
#pragma warning disable SYSLIB0021
            using var aes = new AesManaged();
#pragma warning restore SYSLIB0021
            aes.Key = Key32;
            aes.IV  = Iv16;
            return aes.CreateEncryptor();
        }

        public static byte[] AesGcmEncrypt()
        {
            var nonce      = new byte[AesGcm.NonceByteSizes.MaxSize];
            var tag        = new byte[AesGcm.TagByteSizes.MaxSize];
            var ciphertext = new byte[Data.Length];
            using var aesGcm = new AesGcm(Key32, tag.Length);
            aesGcm.Encrypt(nonce, Data, ciphertext, tag);
            return ciphertext;
        }

        public static byte[] AesCcmEncrypt()
        {
            var nonce      = new byte[AesCcm.NonceByteSizes.MaxSize];
            var tag        = new byte[AesCcm.TagByteSizes.MaxSize];
            var ciphertext = new byte[Data.Length];
            using var aesCcm = new AesCcm(Key32);
            aesCcm.Encrypt(nonce, Data, ciphertext, tag);
            return ciphertext;
        }

        // ChaCha20-Poly1305 (.NET 8+)
        public static byte[] ChaCha20Poly1305Encrypt()
        {
            var nonce      = new byte[12];
            var tag        = new byte[16];
            var ciphertext = new byte[Data.Length];
            using var chacha = new ChaCha20Poly1305(Key32);
            chacha.Encrypt(nonce, Data, ciphertext, tag);
            return ciphertext;
        }

        public static ICryptoTransform TripleDesViaCreate()
        {
            using var des3 = TripleDES.Create();
            des3.Key = Key24;
            des3.IV  = Iv16;
            return des3.CreateEncryptor();
        }

        public static ICryptoTransform TripleDesCbcCreate()
        {
            using var des3 = TripleDES.Create();
            des3.Mode = CipherMode.CBC;
            des3.Key  = Key24;
            des3.IV   = Iv16;
            return des3.CreateEncryptor();
        }

        public static ICryptoTransform TripleDesEcbCreate()
        {
            using var des3 = TripleDES.Create();
            des3.Mode = CipherMode.ECB;
            des3.Key  = Key24;
            return des3.CreateEncryptor();
        }

        public static ICryptoTransform TripleDesCspLegacy()
        {
#pragma warning disable SYSLIB0021
            using var des3 = new TripleDESCryptoServiceProvider();
#pragma warning restore SYSLIB0021
            des3.Key = Key24;
            des3.IV  = Iv16;
            return des3.CreateEncryptor();
        }

        public static ICryptoTransform DesViaCreate()
        {
            using var des = DES.Create();
            des.Key = new byte[8];
            des.IV  = new byte[8];
            return des.CreateEncryptor();
        }

        public static ICryptoTransform DesCspLegacy()
        {
#pragma warning disable SYSLIB0021
            using var des = new DESCryptoServiceProvider();
#pragma warning restore SYSLIB0021
            des.Key = new byte[8];
            des.IV  = new byte[8];
            return des.CreateEncryptor();
        }

        public static ICryptoTransform Rc2ViaCreate()
        {
            using var rc2 = RC2.Create();
            return rc2.CreateEncryptor();
        }

        public static ICryptoTransform Rc2CspLegacy()
        {
#pragma warning disable SYSLIB0021
            using var rc2 = new RC2CryptoServiceProvider();
#pragma warning restore SYSLIB0021
            return rc2.CreateEncryptor();
        }

        public static ICryptoTransform? SymmetricAlgorithmStringFactory()
        {
#pragma warning disable SYSLIB0045
            using var sym = SymmetricAlgorithm.Create("AES");
#pragma warning restore SYSLIB0045
            return sym?.CreateEncryptor();
        }
    }

    // =========================================================================
    // RSA
    // Covers: RSA.Create(), RSACryptoServiceProvider, RSAOpenSsl,
    //         OAEP (SHA1/256/384/512), PKCS#1 v1.5, PSS signing/verification,
    //         span-based Try* overloads (.NET 5+).
    // Expected algo tags: rsa-keygen, rsa-oaep-sha1/sha256/sha384/sha512,
    //                     rsa-pkcs1v15, rsa-pss-sign-*, rsa-pkcs1-sign-*
    // =========================================================================
    public static class AsymmetricRsaTests
    {
        private static readonly byte[] Data = new byte[64];

        public static RSA RsaCreateDefault() => RSA.Create();
        public static RSA RsaCreate2048()    => RSA.Create(2048);
        public static RSA RsaCreate4096()    => RSA.Create(4096);
        public static RSA RsaCreate512()     => RSA.Create(512);
        public static RSA RsaCreate1024()    => RSA.Create(1024);

        public static RSACryptoServiceProvider RsaCspConstructor() =>
            new RSACryptoServiceProvider(2048);

        [SupportedOSPlatform("linux")]
        [SupportedOSPlatform("macos")]
        public static RSAOpenSsl RsaOpenSslConstructor() => new RSAOpenSsl(2048);

        // OAEP encryption / decryption
        public static byte[] RsaOaepSha1Encrypt(RSA rsa)   => rsa.Encrypt(Data, RSAEncryptionPadding.OaepSHA1);
        public static byte[] RsaOaepSha256Encrypt(RSA rsa) => rsa.Encrypt(Data, RSAEncryptionPadding.OaepSHA256);
        public static byte[] RsaOaepSha384Encrypt(RSA rsa) => rsa.Encrypt(Data, RSAEncryptionPadding.OaepSHA384);
        public static byte[] RsaOaepSha512Encrypt(RSA rsa) => rsa.Encrypt(Data, RSAEncryptionPadding.OaepSHA512);

        public static byte[] RsaOaepSha256Decrypt(RSA rsa, byte[] ct) =>
            rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA256);

        // PKCS#1 v1.5 encryption / decryption
        public static byte[] RsaPkcs1Encrypt(RSA rsa)              => rsa.Encrypt(Data, RSAEncryptionPadding.Pkcs1);
        public static byte[] RsaPkcs1Decrypt(RSA rsa, byte[] ct)   => rsa.Decrypt(ct,   RSAEncryptionPadding.Pkcs1);

        // PSS signing / verification
        public static byte[] RsaPssSha256Sign(RSA rsa) =>
            rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        public static byte[] RsaPssSha384Sign(RSA rsa) =>
            rsa.SignData(Data, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        public static byte[] RsaPssSha512Sign(RSA rsa) =>
            rsa.SignData(Data, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        public static bool RsaPssSha256Verify(RSA rsa, byte[] sig) =>
            rsa.VerifyData(Data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // PKCS#1 v1.5 signing / verification
        public static byte[] RsaPkcs1Sha256Sign(RSA rsa) =>
            rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        public static byte[] RsaPkcs1Sha1Sign(RSA rsa) =>
            rsa.SignData(Data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        public static bool RsaPkcs1Sha256Verify(RSA rsa, byte[] sig) =>
            rsa.VerifyData(Data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // SignHash / VerifyHash
        public static byte[] RsaPssSha256SignHash(RSA rsa, byte[] hash) =>
            rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        public static bool RsaPkcs1Sha256VerifyHash(RSA rsa, byte[] hash, byte[] sig) =>
            rsa.VerifyHash(hash, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Span-based Try* overloads (.NET 5+)
        public static bool RsaTryEncryptOaep256(RSA rsa, Span<byte> dest)
            => rsa.TryEncrypt(Data, dest, RSAEncryptionPadding.OaepSHA256, out _);
        public static bool RsaTryDecryptOaep256(RSA rsa, Span<byte> dest, byte[] ct)
            => rsa.TryDecrypt(ct, dest, RSAEncryptionPadding.OaepSHA256, out _);
        public static bool RsaTryEncryptPkcs1(RSA rsa, Span<byte> dest)
            => rsa.TryEncrypt(Data, dest, RSAEncryptionPadding.Pkcs1, out _);
        public static bool RsaTrySignDataPssSha256(RSA rsa, Span<byte> dest)
            => rsa.TrySignData(Data, dest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, out _);
        public static bool RsaTrySignDataPkcs1Sha256(RSA rsa, Span<byte> dest)
            => rsa.TrySignData(Data, dest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, out _);
        public static bool RsaTryVerifyDataPssSha256(RSA rsa, byte[] sig)
            => rsa.VerifyData(Data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        public static bool RsaTryVerifyDataPkcs1Sha256(RSA rsa, byte[] sig)
            => rsa.VerifyData(Data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        public static bool RsaTrySignHashPss(RSA rsa, byte[] hash, Span<byte> dest)
            => rsa.TrySignHash(hash, dest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, out _);
        public static bool RsaTryVerifyHashPkcs1(RSA rsa, byte[] hash, byte[] sig)
            => rsa.VerifyHash(hash, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Key export
        public static string RsaExportPublicKeyPem(RSA rsa)  => rsa.ExportSubjectPublicKeyInfoPem();
        public static string RsaExportPrivateKeyPem(RSA rsa) => rsa.ExportPkcs8PrivateKeyPem();
        public static string RsaExportRsaPublicPem(RSA rsa)  => rsa.ExportRSAPublicKeyPem();
        public static string RsaExportRsaPrivatePem(RSA rsa) => rsa.ExportRSAPrivateKeyPem();
        public static byte[] RsaExportSubjectPublicKeyInfo(RSA rsa)  => rsa.ExportSubjectPublicKeyInfo();
        public static byte[] RsaExportPkcs8PrivateKey(RSA rsa)       => rsa.ExportPkcs8PrivateKey();
    }

    // =========================================================================
    // ECDSA & ECDH
    // Covers: ECDsa.Create() (default, NIST P-256/384/521, Brainpool),
    //         ECDsaCng, ECDsaOpenSsl, SignData/VerifyData/SignHash/VerifyHash,
    //         ECDiffieHellman.Create() (default, NIST P-256/384/521),
    //         ECDiffieHellmanCng, ECDiffieHellmanOpenSsl,
    //         DeriveKeyMaterial/FromHash/FromHmac/Tls.
    // Expected algo tags: ecdsa-keygen, ecdsa-p256/p384/p521-keygen,
    //                     ecdsa-brainpoolp256r1/p384r1/p512r1-keygen,
    //                     ecdsa-sign-sha256/sha384/sha512,
    //                     ecdh-keygen, ecdh-p256/p384/p521-keygen, ecdh-derive
    // =========================================================================
    public static class AsymmetricEcTests
    {
        private static readonly byte[] Data = new byte[64];

        // ECDSA key generation
        public static ECDsa EcdsaCreateDefault()         => ECDsa.Create();
        public static ECDsa EcdsaCreateP256()            => ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public static ECDsa EcdsaCreateP384()            => ECDsa.Create(ECCurve.NamedCurves.nistP384);
        public static ECDsa EcdsaCreateP521()            => ECDsa.Create(ECCurve.NamedCurves.nistP521);
        public static ECDsa EcdsaCreateBrainpoolP256r1() => ECDsa.Create(ECCurve.NamedCurves.brainpoolP256r1);
        public static ECDsa EcdsaCreateBrainpoolP384r1() => ECDsa.Create(ECCurve.NamedCurves.brainpoolP384r1);
        public static ECDsa EcdsaCreateBrainpoolP512r1() => ECDsa.Create(ECCurve.NamedCurves.brainpoolP512r1);

        [SupportedOSPlatform("windows")]
        public static ECDsaCng EcdsaCngConstructor() => new ECDsaCng(256);

        [SupportedOSPlatform("linux")]
        [SupportedOSPlatform("macos")]
        public static ECDsaOpenSsl EcdsaOpenSslConstructor() =>
            new ECDsaOpenSsl(ECCurve.NamedCurves.nistP256);

        // ECDSA sign / verify
        public static byte[] EcdsaSignDataSha256(ECDsa key) => key.SignData(Data, HashAlgorithmName.SHA256);
        public static byte[] EcdsaSignDataSha384(ECDsa key) => key.SignData(Data, HashAlgorithmName.SHA384);
        public static byte[] EcdsaSignDataSha512(ECDsa key) => key.SignData(Data, HashAlgorithmName.SHA512);
        public static bool   EcdsaVerifyDataSha256(ECDsa key, byte[] sig) =>
            key.VerifyData(Data, sig, HashAlgorithmName.SHA256);
        public static bool   EcdsaVerifyDataSha384(ECDsa key, byte[] sig) =>
            key.VerifyData(Data, sig, HashAlgorithmName.SHA384);
        public static byte[] EcdsaSignHashSha256(ECDsa key, byte[] hash)  => key.SignHash(hash);
        public static bool   EcdsaVerifyHashSha256(ECDsa key, byte[] hash, byte[] sig) =>
            key.VerifyHash(hash, sig);

        // Span-based Try* overloads (.NET 5+)
        public static bool EcdsaTrySignDataSha256(ECDsa key, Span<byte> dest)
            => key.TrySignData(Data, dest, HashAlgorithmName.SHA256, out _);
        public static bool EcdsaTrySignDataSha512(ECDsa key, Span<byte> dest)
            => key.TrySignData(Data, dest, HashAlgorithmName.SHA512, out _);
        public static bool EcdsaTryVerifyDataSha256(ECDsa key, byte[] sig)
            => key.VerifyData(Data, sig, HashAlgorithmName.SHA256);
        public static bool EcdsaTrySignHash(ECDsa key, byte[] hash, Span<byte> dest)
            => key.TrySignHash(hash, dest, out _);
        public static bool EcdsaTryVerifyHash(ECDsa key, byte[] hash, byte[] sig)
            => key.VerifyHash(hash, sig);

        // ECDH key generation
        public static ECDiffieHellman EcdhCreateDefault() => ECDiffieHellman.Create();
        public static ECDiffieHellman EcdhCreateP256()    => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        public static ECDiffieHellman EcdhCreateP384()    => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        public static ECDiffieHellman EcdhCreateP521()    => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521);

        [SupportedOSPlatform("windows")]
        public static ECDiffieHellmanCng EcdhCngConstructor() => new ECDiffieHellmanCng(256);

        [SupportedOSPlatform("linux")]
        [SupportedOSPlatform("macos")]
        public static ECDiffieHellmanOpenSsl EcdhOpenSslConstructor() =>
            new ECDiffieHellmanOpenSsl(ECCurve.NamedCurves.nistP256);

        // ECDH key derivation
        public static byte[] EcdhDeriveKeyMaterial(ECDiffieHellman local, ECDiffieHellmanPublicKey remote) =>
            local.DeriveKeyMaterial(remote);
        public static byte[] EcdhDeriveKeyFromHash(ECDiffieHellman local, ECDiffieHellmanPublicKey remote) =>
            local.DeriveKeyFromHash(remote, HashAlgorithmName.SHA256);
        public static byte[] EcdhDeriveKeyFromHmac(ECDiffieHellman local, ECDiffieHellmanPublicKey remote) =>
            local.DeriveKeyFromHmac(remote, HashAlgorithmName.SHA256, null);
        public static byte[] EcdhDeriveKeyTls(ECDiffieHellman local, ECDiffieHellmanPublicKey remote) =>
            local.DeriveKeyTls(remote, new byte[64], new byte[64]);
    }

    // =========================================================================
    // DSA
    // Covers: DSA.Create(), DSACryptoServiceProvider, DSAOpenSsl (Linux/macOS),
    //         SignData, VerifyData, CreateSignature, VerifySignature.
    // Expected algo tags: dsa-keygen, dsa-sign
    // =========================================================================
    public static class DsaTests
    {
        private static readonly byte[] Data = new byte[64];

        public static DSA DsaCreate() => DSA.Create();
        public static DSA DsaCreate512()  => DSA.Create(512);
        public static DSA DsaCreate1024() => DSA.Create(1024);
        public static DSA DsaCreate3072() => DSA.Create(3072);
        public static DSA DsaCreate4096() => DSA.Create(4096);

        public static DSACryptoServiceProvider DsaCspConstructor() =>
            new DSACryptoServiceProvider(1024);

        [SupportedOSPlatform("linux")]
        [SupportedOSPlatform("macos")]
        public static DSAOpenSsl DsaOpenSslConstructor() => new DSAOpenSsl(2048);

        public static byte[] DsaSignData(DSA key)               => key.SignData(Data, HashAlgorithmName.SHA256);
        public static bool   DsaVerifyData(DSA key, byte[] sig) => key.VerifyData(Data, sig, HashAlgorithmName.SHA256);

        public static byte[] DsaCreateSignature(DSACryptoServiceProvider key)            => key.CreateSignature(Data);
        public static bool   DsaVerifySignature(DSACryptoServiceProvider key, byte[] sig) => key.VerifySignature(Data, sig);

        // Span-based Try* overloads (.NET 5+)
        public static bool DsaTrySignData(DSA key, Span<byte> dest)
            => key.TrySignData(Data, dest, HashAlgorithmName.SHA256, out _);
        public static bool DsaTryVerifyData(DSA key, byte[] sig)
            => key.VerifyData(Data, sig, HashAlgorithmName.SHA256);
        public static bool DsaTryCreateSignature(DSACryptoServiceProvider key, Span<byte> dest)
            => key.TryCreateSignature(Data, dest, out _);
    }

    // =========================================================================
    // Key Derivation Functions
    // Covers: Rfc2898DeriveBytes constructor (SHA-1 default + explicit hash),
    //         Rfc2898DeriveBytes.Pbkdf2 static one-shot (.NET 6+),
    //         PasswordDeriveBytes (deprecated PBKDF1),
    //         HKDF.DeriveKey / Extract / Expand (.NET 5+).
    // Expected algo tags: pbkdf2-sha1, pbkdf2-sha256, pbkdf2-sha384,
    //                     pbkdf2-sha512, pbkdf2, pbkdf1,
    //                     hkdf-sha256, hkdf-sha384, hkdf-sha512, hkdf
    // =========================================================================
    public static class KdfTests
    {
        private static readonly byte[] Salt = new byte[16];

        public static byte[] Pbkdf2Sha1DefaultConstructor()
        {
            // Older 3-arg overload; SHA-1 is the implicit default
#pragma warning disable SYSLIB0060
            using var kdf = new Rfc2898DeriveBytes("password", Salt, 100_000);
#pragma warning restore SYSLIB0060
            return kdf.GetBytes(32);
        }

        public static byte[] Pbkdf2Sha256Constructor()
        {
            using var kdf = new Rfc2898DeriveBytes("password", Salt, 100_000, HashAlgorithmName.SHA256);
            return kdf.GetBytes(32);
        }

        public static byte[] Pbkdf2Sha384Constructor()
        {
            using var kdf = new Rfc2898DeriveBytes("password", Salt, 100_000, HashAlgorithmName.SHA384);
            return kdf.GetBytes(32);
        }

        public static byte[] Pbkdf2Sha512Constructor()
        {
            using var kdf = new Rfc2898DeriveBytes("password", Salt, 100_000, HashAlgorithmName.SHA512);
            return kdf.GetBytes(32);
        }

        public static byte[] Pbkdf2Sha256Static() =>
            Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes("password"), Salt, 100_000, HashAlgorithmName.SHA256, 32);

        public static byte[] Pbkdf2Sha1Static() =>
            Rfc2898DeriveBytes.Pbkdf2("password", Salt, 100_000, HashAlgorithmName.SHA1, 20);

        public static byte[] Pbkdf2Sha384Static() =>
            Rfc2898DeriveBytes.Pbkdf2("password", Salt, 100_000, HashAlgorithmName.SHA384, 32);

        public static byte[] Pbkdf2Sha512Static() =>
            Rfc2898DeriveBytes.Pbkdf2("password", Salt, 100_000, HashAlgorithmName.SHA512, 32);

        public static byte[] Pbkdf1Legacy()
        {
#pragma warning disable SYSLIB0041
            using var kdf = new PasswordDeriveBytes("password", Salt);
            return kdf.GetBytes(20);
#pragma warning restore SYSLIB0041
        }
    }

    // =========================================================================
    // HKDF
    // Covers: HKDF.DeriveKey, HKDF.Extract, HKDF.Expand (.NET 5+).
    // Expected algo tags: hkdf-sha256, hkdf-sha384, hkdf-sha512, hkdf
    // =========================================================================
    public static class HkdfTests
    {
        private static readonly byte[] Ikm  = new byte[32];
        private static readonly byte[] Salt = new byte[32];
        private static readonly byte[] Info = new byte[16];

        public static byte[] DeriveKeySha256() =>
            HKDF.DeriveKey(HashAlgorithmName.SHA256, Ikm, 32, Salt, Info);

        public static byte[] DeriveKeySha384() =>
            HKDF.DeriveKey(HashAlgorithmName.SHA384, Ikm, 48, Salt, Info);

        public static byte[] DeriveKeySha512() =>
            HKDF.DeriveKey(HashAlgorithmName.SHA512, Ikm, 64, Salt, Info);

        public static byte[] ExtractSha256() =>
            HKDF.Extract(HashAlgorithmName.SHA256, Ikm, Salt);

        public static byte[] ExpandSha256(byte[] prk) =>
            HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, Info);

        public static byte[] DeriveKeySha1() =>
            HKDF.DeriveKey(HashAlgorithmName.SHA1, Ikm, 20, Salt, Info);

        public static byte[] DeriveKeyMd5() =>
            HKDF.DeriveKey(HashAlgorithmName.MD5, Ikm, 16, Salt, Info);
    }

    // =========================================================================
    // Cryptographically Secure Random Number Generation
    // Covers: RandomNumberGenerator static utility methods (.NET 6+),
    //         RandomNumberGenerator.Create() instance,
    //         RNGCryptoServiceProvider (deprecated).
    // Expected algo tags: csprng
    // =========================================================================
    public static class RandomTests
    {
        public static byte[] RngGetBytes()          => RandomNumberGenerator.GetBytes(32);
        public static int    RngGetInt32InRange()   => RandomNumberGenerator.GetInt32(0, 100);
        public static int    RngGetInt32Max()       => RandomNumberGenerator.GetInt32(256);
        public static string RngGetHexString()      => RandomNumberGenerator.GetHexString(64);
        public static string RngGetString()         =>
            RandomNumberGenerator.GetString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 16);

        public static void RngFill()
        {
            var buffer = new byte[32];
            RandomNumberGenerator.Fill(buffer);
        }

        public static byte[] RngCreateInstance()
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[32];
            rng.GetBytes(bytes);
            return bytes;
        }

        public static byte[] RngGetNonZeroBytes()
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[32];
            rng.GetNonZeroBytes(bytes);
            return bytes;
        }

        public static byte[] RngCspLegacy()
        {
#pragma warning disable SYSLIB0023
            using var rng = new RNGCryptoServiceProvider();
#pragma warning restore SYSLIB0023
            var bytes = new byte[32];
            rng.GetBytes(bytes);
            return bytes;
        }
    }

    // =========================================================================
    // X.509 / PKI
    // Covers: X509Certificate2 constructors and factory methods,
    //         CertificateRequest (CSR), CreateSelfSigned,
    //         X509Store, X509Chain.Build.
    // Expected algo tags: x509-certificate, x509-csr, x509-self-signed,
    //                     x509-store, x509-chain-verify
    // =========================================================================
    public static class PkiX509Tests
    {
        public static X509Certificate2 LoadFromBytes(byte[] certData)              => new X509Certificate2(certData);
        public static X509Certificate2 LoadFromFile(string path)                   => new X509Certificate2(path);
        public static X509Certificate2 LoadFromFileWithPassword(string p, string pw) => new X509Certificate2(p, pw);
        public static X509Certificate2 LoadFromPem(string certPem)                 => X509Certificate2.CreateFromPem(certPem);
        public static X509Certificate2 LoadFromPemWithKey(string cert, string key) => X509Certificate2.CreateFromPem(cert, key);

        public static CertificateRequest CreateCsrWithEcdsa()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new CertificateRequest("CN=test.example.com", key, HashAlgorithmName.SHA256);
        }

        public static CertificateRequest CreateCsrWithRsa()
        {
            using var key = RSA.Create(2048);
            return new CertificateRequest(
                "CN=test.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public static X509Certificate2 CreateSelfSignedEcdsa()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest("CN=test.example.com", key, HashAlgorithmName.SHA256);
            return req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        }

        public static X509Certificate2 CreateSelfSignedRsa()
        {
            using var key = RSA.Create(2048);
            var req = new CertificateRequest(
                "CN=test.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        }

        public static void OpenPersonalStore()
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
        }

        public static void OpenRootStore()
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
        }

        public static void OpenCustomStore(string name)
        {
            using var store = new X509Store(name, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
        }

        public static bool ValidateCertificateChain(X509Certificate2 cert)
        {
            using var chain = new X509Chain();
            return chain.Build(cert);
        }

        public static bool ValidateWithCustomPolicy(X509Certificate2 cert)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(cert);
        }

        // Certificate export
        public static string ExportAsPem(X509Certificate2 cert)    => cert.ExportCertificatePem();
        public static byte[] ExportAsDer(X509Certificate2 cert)    => cert.Export(X509ContentType.Cert);
        public static byte[] ExportRawCertData(X509Certificate2 c) => c.GetRawCertData();
    }

    // =========================================================================
    // DPAPI (Windows-only)
    // Covers: ProtectedData.Protect/Unprotect (user and machine scopes),
    //         ProtectedMemory.Protect/Unprotect (in-process scope).
    // Expected algo tags: dpapi-protect, dpapi-unprotect,
    //                     dpapi-memory-protect, dpapi-memory-unprotect
    // =========================================================================
    [SupportedOSPlatform("windows")]
    public static class DpapiTests
    {
        private static readonly byte[] PlainText = new byte[64];
        private static readonly byte[] Entropy   = new byte[16];

        public static byte[] ProtectCurrentUser()              => ProtectedData.Protect(PlainText, Entropy, DataProtectionScope.CurrentUser);
        public static byte[] ProtectLocalMachine()             => ProtectedData.Protect(PlainText, null, DataProtectionScope.LocalMachine);
        public static byte[] UnprotectCurrentUser(byte[] ct)  => ProtectedData.Unprotect(ct, Entropy, DataProtectionScope.CurrentUser);
        public static byte[] UnprotectLocalMachine(byte[] ct) => ProtectedData.Unprotect(ct, null, DataProtectionScope.LocalMachine);

        public static void ProtectMemory(byte[] data)          => ProtectedMemory.Protect(data, MemoryProtectionScope.SameProcess);
        public static void ProtectMemoryCrossProcess(byte[] d) => ProtectedMemory.Protect(d, MemoryProtectionScope.CrossProcess);
        public static void UnprotectMemory(byte[] data)        => ProtectedMemory.Unprotect(data, MemoryProtectionScope.SameProcess);
    }

    // =========================================================================
    // Miscellaneous
    // Covers: CryptographicOperations.FixedTimeEquals (timing-safe comparison),
    //         CryptographicOperations.ZeroMemory (secure memory clearing).
    // Expected algo tags: fixed-time-compare, zero-memory
    // =========================================================================
    public static class MiscCryptoTests
    {
        public static bool TimingSafeCompare(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
            CryptographicOperations.FixedTimeEquals(a, b);

        public static bool TokenVerify(byte[] expected, byte[] received) =>
            CryptographicOperations.FixedTimeEquals(expected, received);

        public static void SecureZero(Span<byte> sensitiveData) =>
            CryptographicOperations.ZeroMemory(sensitiveData);

        public static void ClearKey(byte[] key) =>
            CryptographicOperations.ZeroMemory(key);
    }

    // =========================================================================
    // One-shot symmetric APIs (.NET 6+) and AEAD encrypt/decrypt operations
    // Expected algo tags: aes-cbc, aes-ecb, aes-cfb, 3des-cbc, 3des-ecb,
    //                     aes-gcm, aes-ccm, chacha20-poly1305
    // =========================================================================
    public static class SymmetricOneShotTests
    {
        private static readonly byte[] Key   = new byte[32];
        private static readonly byte[] Iv    = new byte[16];
        private static readonly byte[] Nonce = new byte[12];
        private static readonly byte[] Tag   = new byte[16];
        private static readonly byte[] Data  = new byte[64];

        public static byte[] AesEncryptCbcOneShot()
        {
            using var aes = Aes.Create();
            return aes.EncryptCbc(Data, Iv);
        }

        public static byte[] AesDecryptCbcOneShot(byte[] ciphertext)
        {
            using var aes = Aes.Create();
            return aes.DecryptCbc(ciphertext, Iv);
        }

        public static byte[] AesEncryptEcbOneShot()
        {
            using var aes = Aes.Create();
            return aes.EncryptEcb(Data, PaddingMode.PKCS7);
        }

        public static byte[] AesDecryptEcbOneShot(byte[] ciphertext)
        {
            using var aes = Aes.Create();
            return aes.DecryptEcb(ciphertext, PaddingMode.PKCS7);
        }

        public static byte[] AesEncryptCfbOneShot()
        {
            using var aes = Aes.Create();
            return aes.EncryptCfb(Data, Iv);
        }

        public static byte[] TripleDesEncryptCbcOneShot()
        {
            using var tdes = TripleDES.Create();
            return tdes.EncryptCbc(Data, new byte[8]);
        }

        public static byte[] TripleDesEncryptEcbOneShot()
        {
            using var tdes = TripleDES.Create();
            return tdes.EncryptEcb(Data, PaddingMode.PKCS7);
        }

        public static byte[] AesGcmRoundTrip()
        {
            var ciphertext = new byte[Data.Length];
            using var gcm = new AesGcm(Key, 16);
            gcm.Encrypt(Nonce, Data, ciphertext, Tag);
            var plaintext = new byte[ciphertext.Length];
            gcm.Decrypt(Nonce, ciphertext, Tag, plaintext);
            return plaintext;
        }

        [SupportedOSPlatform("windows")]
        public static byte[] AesCcmRoundTrip()
        {
            var ciphertext = new byte[Data.Length];
            using var ccm = new AesCcm(Key);
            ccm.Encrypt(Nonce, Data, ciphertext, Tag);
            var plaintext = new byte[ciphertext.Length];
            ccm.Decrypt(Nonce, ciphertext, Tag, plaintext);
            return plaintext;
        }

        public static byte[] ChaCha20Poly1305RoundTrip()
        {
            var ciphertext = new byte[Data.Length];
            using var chacha = new ChaCha20Poly1305(Key);
            chacha.Encrypt(Nonce, Data, ciphertext, Tag);
            var plaintext = new byte[ciphertext.Length];
            chacha.Decrypt(Nonce, ciphertext, Tag, plaintext);
            return plaintext;
        }
    }

    // =========================================================================
    // Explicit mode, padding and key-size configuration
    // Expected algo tags: aes-ecb, aes-padding-none, aes-128, aes-256,
    //                     rijndael-cbc, rsa-4096, rsa-3072-keygen,
    //                     rsa-2048-keygen, dsa-2048-keygen, 3des-192
    // =========================================================================
    public static class AlgorithmConfigurationTests
    {
        public static ICryptoTransform AesEcbNoPadding()
        {
            var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.KeySize = 128;
            return aes.CreateEncryptor();
        }

        public static SymmetricAlgorithm AesViaObjectInitializer() =>
#pragma warning disable SYSLIB0021
            new AesManaged { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7, KeySize = 256 };
#pragma warning restore SYSLIB0021

        public static SymmetricAlgorithm TripleDesWithKeySize()
        {
            var tdes = TripleDES.Create();
            tdes.KeySize = 192;
            return tdes;
        }

        public static RSA RsaWithKeySizeProperty()
        {
            var rsa = RSA.Create();
            rsa.KeySize = 4096;
            return rsa;
        }

        public static RSA Rsa3072()          => RSA.Create(3072);
        public static RSA Rsa2048Csp()       => new RSACryptoServiceProvider(2048);
        public static DSA Dsa2048()          => DSA.Create(2048);

        // Key size resolved through a local variable
        public static RSA RsaFromLocalKeySize()
        {
            int keySize = 8192;
            return RSA.Create(keySize);
        }
    }

    // =========================================================================
    // Remaining cipher-mode / padding-mode / key-size combinations for
    // DES, RC2 and Rijndael (AES/TripleDES combinations covered above).
    // Expected algo tags: des-ecb, des-ofb, des-cfb, rc2-cbc, rc2-ecb, rc2-ofb,
    //   rc2-cfb, rijndael-cbc, rijndael-ecb, rijndael-cfb, rijndael-ofb,
    //   3des-padding-zeros, des-padding-ansix923, rc2-padding-iso10126,
    //   rijndael-padding-zeros, des-64, rc2-40, rc2-128, rijndael-192,
    //   rijndael-256, aes-192
    // =========================================================================
    public static class RemainingSymmetricConfigTests
    {
        public static SymmetricAlgorithm DesEcb()
        {
            var des = DES.Create();
            des.Mode = CipherMode.ECB;
            return des;
        }

        public static SymmetricAlgorithm DesOfb()
        {
            var des = DES.Create();
            des.Mode = CipherMode.OFB;
            return des;
        }

        public static SymmetricAlgorithm DesCfb()
        {
            var des = DES.Create();
            des.Mode = CipherMode.CFB;
            return des;
        }

        public static SymmetricAlgorithm Rc2Cbc()
        {
            var rc2 = RC2.Create();
            rc2.Mode = CipherMode.CBC;
            return rc2;
        }

        public static SymmetricAlgorithm Rc2Ecb()
        {
            var rc2 = RC2.Create();
            rc2.Mode = CipherMode.ECB;
            return rc2;
        }

        public static SymmetricAlgorithm Rc2Ofb()
        {
            var rc2 = RC2.Create();
            rc2.Mode = CipherMode.OFB;
            return rc2;
        }

        public static SymmetricAlgorithm Rc2Cfb()
        {
            var rc2 = RC2.Create();
            rc2.Mode = CipherMode.CFB;
            return rc2;
        }

        public static SymmetricAlgorithm RijndaelCbc()
        {
#pragma warning disable SYSLIB0022
            var rijndael = Rijndael.Create();
#pragma warning restore SYSLIB0022
            rijndael.Mode = CipherMode.CBC;
            return rijndael;
        }

        public static SymmetricAlgorithm RijndaelEcb()
        {
#pragma warning disable SYSLIB0022
            var rijndael = Rijndael.Create();
#pragma warning restore SYSLIB0022
            rijndael.Mode = CipherMode.ECB;
            return rijndael;
        }

        public static SymmetricAlgorithm RijndaelCfb()
        {
#pragma warning disable SYSLIB0022
            var rijndael = Rijndael.Create();
#pragma warning restore SYSLIB0022
            rijndael.Mode = CipherMode.CFB;
            return rijndael;
        }

        public static SymmetricAlgorithm RijndaelOfb()
        {
#pragma warning disable SYSLIB0022
            var rijndael = Rijndael.Create();
#pragma warning restore SYSLIB0022
            rijndael.Mode = CipherMode.OFB;
            return rijndael;
        }

        public static SymmetricAlgorithm TripleDesPaddingZeros()
        {
            var tdes = TripleDES.Create();
            tdes.Padding = PaddingMode.Zeros;
            return tdes;
        }

        public static SymmetricAlgorithm DesPaddingAnsiX923()
        {
            var des = DES.Create();
            des.Padding = PaddingMode.ANSIX923;
            return des;
        }

        public static SymmetricAlgorithm Rc2PaddingIso10126()
        {
            var rc2 = RC2.Create();
            rc2.Padding = PaddingMode.ISO10126;
            return rc2;
        }

        public static SymmetricAlgorithm RijndaelPaddingZeros()
        {
#pragma warning disable SYSLIB0022
            var rijndael = Rijndael.Create();
#pragma warning restore SYSLIB0022
            rijndael.Padding = PaddingMode.Zeros;
            return rijndael;
        }

        public static SymmetricAlgorithm Des64()
        {
            var des = DES.Create();
            des.KeySize = 64;
            return des;
        }

        public static SymmetricAlgorithm Rc2_40()
        {
            var rc2 = RC2.Create();
            rc2.KeySize = 40;
            return rc2;
        }

        public static SymmetricAlgorithm Rc2_128()
        {
            var rc2 = RC2.Create();
            rc2.KeySize = 128;
            return rc2;
        }

        public static SymmetricAlgorithm Rijndael192()
        {
#pragma warning disable SYSLIB0022
            var rijndael = Rijndael.Create();
#pragma warning restore SYSLIB0022
            rijndael.KeySize = 192;
            return rijndael;
        }

        public static SymmetricAlgorithm Rijndael256()
        {
#pragma warning disable SYSLIB0022
            var rijndael = Rijndael.Create();
#pragma warning restore SYSLIB0022
            rijndael.KeySize = 256;
            return rijndael;
        }

        public static SymmetricAlgorithm Aes192()
        {
            var aes = Aes.Create();
            aes.KeySize = 192;
            return aes;
        }
    }

    // =========================================================================
    // Legacy and string-driven algorithm factories
    // Expected algo tags: ripemd160, hmac-ripemd160, 3des-cbc-mac, rijndael,
    //                     sha1, hmacsha256, sha256, rsa
    // =========================================================================
    public static class LegacyAlgorithmTests
    {
        public static byte[] RipeMd160ViaCreate(byte[] data)
        {
            using var hash = RIPEMD160.Create();
            return hash.ComputeHash(data);
        }

        public static byte[] RipeMd160Managed(byte[] data)
        {
            using var hash = new RIPEMD160Managed();
            return hash.ComputeHash(data);
        }

        public static byte[] HmacRipeMd160(byte[] key, byte[] data)
        {
            using var mac = new HMACRIPEMD160(key);
            return mac.ComputeHash(data);
        }

        public static byte[] MacTripleDesCbc(byte[] key, byte[] data)
        {
            using var mac = new MACTripleDES(key);
            return mac.ComputeHash(data);
        }

#pragma warning disable SYSLIB0022
        public static SymmetricAlgorithm RijndaelViaCreate()   => Rijndael.Create();
        public static SymmetricAlgorithm RijndaelManagedCtor() => new RijndaelManaged();

        public static ICryptoTransform RijndaelCbcEncryptor()
        {
            var rijndael = new RijndaelManaged();
            rijndael.Mode = CipherMode.CBC;
            return rijndael.CreateEncryptor();
        }
#pragma warning restore SYSLIB0022

#pragma warning disable SYSLIB0007
        public static HashAlgorithm DefaultHashFactory()        => HashAlgorithm.Create();
#pragma warning restore SYSLIB0007
#pragma warning disable SYSLIB0045
        public static KeyedHashAlgorithm KeyedHashFactory()     => KeyedHashAlgorithm.Create("HMACSHA256");
#pragma warning restore SYSLIB0045
        public static object CryptoConfigFactory()              => CryptoConfig.CreateFromName("SHA256");
        public static string CryptoConfigOid()                  => CryptoConfig.MapNameToOID("SHA512");
#pragma warning disable SYSLIB0045
        public static AsymmetricAlgorithm AsymmetricFactory()   => AsymmetricAlgorithm.Create("RSA");
#pragma warning restore SYSLIB0045
    }

    // =========================================================================
    // Legacy signature and key-exchange formatters
    // Expected algo tags: rsa-pkcs1-sign, rsa-oaep-keyexchange,
    //                     rsa-pkcs1-keyexchange, dsa-sign
    // =========================================================================
    public static class SignatureFormatterTests
    {
        public static byte[] RsaPkcs1Sign(RSA rsa, byte[] hash)
        {
            var formatter = new RSAPKCS1SignatureFormatter(rsa);
            formatter.SetHashAlgorithm("SHA256");
            return formatter.CreateSignature(hash);
        }

        public static bool RsaPkcs1Verify(RSA rsa, byte[] hash, byte[] signature)
        {
            var deformatter = new RSAPKCS1SignatureDeformatter(rsa);
            deformatter.SetHashAlgorithm("SHA256");
            return deformatter.VerifySignature(hash, signature);
        }

        public static byte[] RsaOaepKeyExchange(RSA rsa, byte[] sessionKey) =>
            new RSAOAEPKeyExchangeFormatter(rsa).CreateKeyExchange(sessionKey);

        public static byte[] RsaPkcs1KeyExchange(RSA rsa, byte[] sessionKey) =>
            new RSAPKCS1KeyExchangeFormatter(rsa).CreateKeyExchange(sessionKey);

        public static byte[] DsaSign(DSA dsa, byte[] hash)
        {
            var formatter = new DSASignatureFormatter(dsa);
            formatter.SetHashAlgorithm("SHA1");
            return formatter.CreateSignature(hash);
        }
    }

    // =========================================================================
    // Named-curve resolution via friendly name and OID
    // Expected algo tags: ecdsa-p256-keygen, ecdsa-p384-keygen,
    //                     ecdsa-secp256k1-keygen, ecdh-p521-keygen
    // =========================================================================
    public static class CurveResolutionTests
    {
        public static ECDsa FromFriendlyName() => ECDsa.Create(ECCurve.CreateFromFriendlyName("secp256r1"));
        public static ECDsa FromCurveOid()     => ECDsa.Create(ECCurve.CreateFromValue("1.3.132.0.34"));
        public static ECDsa Secp256k1()        => ECDsa.Create(ECCurve.CreateFromFriendlyName("secP256k1"));
        public static ECDiffieHellman EcdhFromFriendlyName() =>
            ECDiffieHellman.Create(ECCurve.CreateFromFriendlyName("secp521r1"));
    }

    // =========================================================================
    // RSA key material import
    // Expected algo tag: rsa-key-import
    // =========================================================================
    public static class RsaKeyImportTests
    {
        public static RSA ImportSpki(byte[] blob)
        {
            var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(blob, out _);
            return rsa;
        }

        public static RSA ImportPkcs8(byte[] blob)
        {
            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(blob, out _);
            return rsa;
        }

        public static RSA ImportRsaPrivate(byte[] blob)
        {
            var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(blob, out _);
            return rsa;
        }

        public static RSA ImportPem(string pem)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }
    }

    // =========================================================================
    // CMS / PKCS (System.Security.Cryptography.Pkcs)
    // Expected algo tags: cms-signed, cms-enveloped, cms-signer, cms-recipient,
    //                     cms-sign, cms-verify, cms-encrypt, cms-decrypt,
    //                     pkcs12, rfc3161-timestamp
    // =========================================================================
    public static class CmsTests
    {
        public static byte[] SignDetachedCms(byte[] content, X509Certificate2 signerCert)
        {
            var signedCms = new SignedCms(new ContentInfo(content), detached: true);
            signedCms.ComputeSignature(new CmsSigner(signerCert));
            return signedCms.Encode();
        }

        public static void VerifyCms(byte[] encoded)
        {
            var signedCms = new SignedCms();
            signedCms.Decode(encoded);
            signedCms.CheckSignature(verifySignatureOnly: true);
        }

        public static byte[] EncryptEnveloped(byte[] content, X509Certificate2 recipientCert)
        {
            var envelopedCms = new EnvelopedCms(new ContentInfo(content));
            envelopedCms.Encrypt(new CmsRecipient(recipientCert));
            return envelopedCms.Encode();
        }

        public static byte[] DecryptEnveloped(byte[] encoded)
        {
            var envelopedCms = new EnvelopedCms();
            envelopedCms.Decode(encoded);
            envelopedCms.Decrypt();
            return envelopedCms.ContentInfo.Content;
        }

        public static Pkcs12Builder BuildPkcs12() => new Pkcs12Builder();

        public static Rfc3161TimestampRequest TimestampRequest(byte[] hash) =>
            Rfc3161TimestampRequest.CreateFromHash(hash, HashAlgorithmName.SHA256);
    }

    // =========================================================================
    // XML signature and encryption (System.Security.Cryptography.Xml)
    // Expected algo tags: xmldsig, xmlenc, xmldsig-sign, xmldsig-verify,
    //                     xmlenc-encrypt, xmlenc-decrypt, sha256,
    //                     rsa-pkcs1-sign-sha256, aes-256-cbc, rsa-oaep
    // =========================================================================
    public static class XmlCryptoTests
    {
        public static void SignXml(XmlDocument document, RSA key)
        {
            var signedXml = new SignedXml(document) { SigningKey = key };
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
            var reference = new Reference(string.Empty) { DigestMethod = SignedXml.XmlDsigSHA256Url };
            signedXml.AddReference(reference);
            signedXml.ComputeSignature();
        }

        public static bool VerifyXml(XmlDocument document, RSA key)
        {
            var signedXml = new SignedXml(document);
            return signedXml.CheckSignature(key);
        }

        public static byte[] EncryptXmlElement(XmlElement element, SymmetricAlgorithm key)
        {
            var encryptedXml = new EncryptedXml();
            return encryptedXml.EncryptData(element, key, false);
        }

        public static byte[] DecryptXmlElement(byte[] cipherValue, SymmetricAlgorithm key)
        {
            var encryptedXml = new EncryptedXml();
            return encryptedXml.DecryptData(new EncryptedData(), key);
        }

        public static string[] AlgorithmUris() => new[]
        {
            SignedXml.XmlDsigRSASHA1Url,
            SignedXml.XmlDsigRSASHA512Url,
            SignedXml.XmlDsigHMACSHA1Url,
            EncryptedXml.XmlEncAES256Url,
            EncryptedXml.XmlEncTripleDESUrl,
            EncryptedXml.XmlEncRSAOAEPUrl,
            EncryptedXml.XmlEncAES256KeyWrapUrl
        };
    }

    // =========================================================================
    // Fallback paths where the algorithm argument is not statically resolvable
    // Expected algo tags: hash, hmac, pbkdf2, rsa-encrypt, rsa-sign, aes-ofb
    // =========================================================================
    public static class UnresolvableArgumentTests
    {
        public static IncrementalHash IncrementalHashOf(HashAlgorithmName name) =>
            IncrementalHash.CreateHash(name);

        public static IncrementalHash IncrementalHmacOf(HashAlgorithmName name, byte[] key) =>
            IncrementalHash.CreateHMAC(name, key);

        public static byte[] Pbkdf2Of(byte[] password, byte[] salt, HashAlgorithmName name) =>
            Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, name, 32);

        public static byte[] RsaEncryptWith(RSA rsa, byte[] data, RSAEncryptionPadding padding) =>
            rsa.Encrypt(data, padding);

        public static byte[] RsaSignWith(RSA rsa, byte[] data, HashAlgorithmName name, RSASignaturePadding padding) =>
            rsa.SignData(data, name, padding);

        public static ICryptoTransform AesOfbEncryptor()
        {
            var aes = Aes.Create();
            aes.Mode = CipherMode.OFB;
            return aes.CreateEncryptor();
        }
    }

    // =========================================================================
    // Remaining XML signature / encryption algorithm URIs
    // Expected algo tags: sha1, sha384, sha512, dsa-sign, rsa-pkcs1-sign-sha384,
    //                     aes-128-cbc, aes-192-cbc, aes-128-kw, aes-192-kw,
    //                     3des-kw, rsa-pkcs1v15
    // =========================================================================
    public static class XmlCryptoAlgorithmUriTests
    {
        public static string[] SignatureUris() => new[]
        {
            SignedXml.XmlDsigSHA1Url,
            SignedXml.XmlDsigSHA384Url,
            SignedXml.XmlDsigSHA512Url,
            SignedXml.XmlDsigDSAUrl,
            SignedXml.XmlDsigRSASHA384Url
        };

        public static string[] EncryptionUris() => new[]
        {
            EncryptedXml.XmlEncAES128Url,
            EncryptedXml.XmlEncAES192Url,
            EncryptedXml.XmlEncAES128KeyWrapUrl,
            EncryptedXml.XmlEncAES192KeyWrapUrl,
            EncryptedXml.XmlEncTripleDESKeyWrapUrl,
            EncryptedXml.XmlEncRSA15Url
        };

        public static byte[] WrapKey(byte[] keyData, SymmetricAlgorithm kek) =>
            EncryptedXml.EncryptKey(keyData, kek);

        public static byte[] UnwrapKey(byte[] keyData, SymmetricAlgorithm kek) =>
            new EncryptedXml().DecryptKey(keyData, kek);

        public static void DecryptWholeDocument(XmlDocument document) =>
            new EncryptedXml(document).DecryptDocument();
    }

    // =========================================================================
    // Span-based one-shot APIs, async hashing and remaining PKCS types
    // Expected algo tags: aes-cbc, aes-ecb, aes-cfb, sha256, pkcs8, pkcs12,
    //                     ecdh-secp256k1-keygen, rijndael-encrypt
    // =========================================================================
    public static class RemainingCoverageTests
    {
        private static readonly byte[] Iv = new byte[16];

        public static bool TryOneShots(Span<byte> destination, byte[] data)
        {
            using var aes = Aes.Create();
            return aes.TryEncryptCbc(data, Iv, destination, out _)
                && aes.TryDecryptCbc(data, Iv, destination, out _)
                && aes.TryEncryptEcb(data, destination, PaddingMode.PKCS7, out _)
                && aes.TryDecryptEcb(data, destination, PaddingMode.PKCS7, out _)
                && aes.TryEncryptCfb(data, Iv, destination, out _)
                && aes.TryDecryptCfb(data, Iv, destination, out _);
        }

        public static byte[] DecryptCfbOneShot(byte[] ciphertext)
        {
            using var aes = Aes.Create();
            return aes.DecryptCfb(ciphertext, Iv);
        }

        public static ValueTask<byte[]> HashStreamAsync(Stream source) =>
            SHA256.HashDataAsync(source);

        // No Mode assignment, so the cipher-type fallback applies
#pragma warning disable SYSLIB0022
        public static ICryptoTransform RijndaelDefaultMode() =>
            new RijndaelManaged().CreateEncryptor();
#pragma warning restore SYSLIB0022

        public static ECDiffieHellman EcdhSecp256k1() =>
            ECDiffieHellman.Create(ECCurve.CreateFromValue("1.3.132.0.10"));

        public static Pkcs8PrivateKeyInfo ExportPkcs8Info(RSA key) =>
            Pkcs8PrivateKeyInfo.Create(key);

        public static Pkcs12Info ReadPkcs12(byte[] blob) =>
            Pkcs12Info.Decode(blob, out _);
    }

    // =========================================================================
    // DSACng
    // Covers: new DSACng(keySize), DSACng.SignData/VerifyData, KeySize property
    // Expected algo tags: dsa-2048-keygen, dsa-sign
    // =========================================================================
    public static class DsaCngTests
    {
        private static readonly byte[] Data = new byte[64];

        [SupportedOSPlatform("windows")]
        public static DSACng DsaCngConstructor() => new DSACng(2048);

        [SupportedOSPlatform("windows")]
        public static byte[] DsaCngSignData(DSACng key) => key.SignData(Data, HashAlgorithmName.SHA256);
        [SupportedOSPlatform("windows")]
        public static bool   DsaCngVerifyData(DSACng key, byte[] sig) =>
            key.VerifyData(Data, sig, HashAlgorithmName.SHA256);
    }

    // =========================================================================
    // Post-quantum cryptography: ML-DSA, ML-KEM, SLH-DSA (.NET 9/10+)
    // Expected algo tags: ml-dsa-65-keygen, ml-dsa-sign, ml-dsa-key-export,
    //                     ml-dsa-key-import, ml-kem-768-keygen,
    //                     ml-kem-encapsulate, ml-kem-decapsulate,
    //                     ml-kem-key-export, ml-kem-key-import,
    //                     slh-dsa-shake-128s-keygen, slh-dsa-sign,
    //                     slh-dsa-key-export, slh-dsa-key-import
    // =========================================================================
    public static class PostQuantumTests
    {
        private static readonly byte[] Data = new byte[64];
        private static readonly byte[] Blob = new byte[32];

        public static MLDsa MLDsaGenerateKey() => MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        public static byte[] MLDsaSign(MLDsa key) => key.SignData(Data);
        public static bool   MLDsaVerify(MLDsa key, byte[] sig) => key.VerifyData(Data, sig);
        public static byte[] MLDsaExportPublicKey(MLDsa key) => key.ExportMLDsaPublicKey();
        public static MLDsa MLDsaImportPrivateKey() => MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm.MLDsa65, Blob);
        public static MLDsa MLDsaGenerateKey44() => MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
        public static MLDsa MLDsaGenerateKey87() => MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87);

        public static MLKem MLKemGenerateKey() => MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        public static byte[] MLKemEncapsulate(MLKem key)
        {
            key.Encapsulate(out var ciphertext, out var sharedSecret);
            return sharedSecret;
        }
        public static byte[] MLKemDecapsulate(MLKem key, byte[] ciphertext) => key.Decapsulate(ciphertext);
        public static byte[] MLKemExportKey(MLKem key) => key.ExportEncapsulationKey();
        public static MLKem MLKemImportKey() => MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, Blob);
        public static MLKem MLKemGenerateKey512() => MLKem.GenerateKey(MLKemAlgorithm.MLKem512);
        public static MLKem MLKemGenerateKey1024() => MLKem.GenerateKey(MLKemAlgorithm.MLKem1024);

        public static SlhDsa SlhDsaGenerateKey() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake128s);
        public static byte[] SlhDsaSign(SlhDsa key) => key.SignData(Data);
        public static bool   SlhDsaVerify(SlhDsa key, byte[] sig) => key.VerifyData(Data, sig);
        public static byte[] SlhDsaExportKey(SlhDsa key) => key.ExportSlhDsaPublicKey();
        public static SlhDsa SlhDsaImportKey() => SlhDsa.ImportSlhDsaPrivateKey(SlhDsaAlgorithm.SlhDsaShake128s, Blob);

        public static SlhDsa SlhDsaGenerateKeySha2_128s() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
        public static SlhDsa SlhDsaGenerateKeySha2_128f() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128f);
        public static SlhDsa SlhDsaGenerateKeySha2_192s() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_192s);
        public static SlhDsa SlhDsaGenerateKeySha2_192f() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_192f);
        public static SlhDsa SlhDsaGenerateKeySha2_256s() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_256s);
        public static SlhDsa SlhDsaGenerateKeySha2_256f() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_256f);
        public static SlhDsa SlhDsaGenerateKeyShake128f() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake128f);
        public static SlhDsa SlhDsaGenerateKeyShake192s() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake192s);
        public static SlhDsa SlhDsaGenerateKeyShake192f() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake192f);
        public static SlhDsa SlhDsaGenerateKeyShake256s() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake256s);
        public static SlhDsa SlhDsaGenerateKeyShake256f() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake256f);
    }

    // =========================================================================
    // KMAC (.NET 9+), including the KmacXof extendable-output variants
    // Expected algo tags: kmac128, kmac256, kmac-xof128, kmac-xof256
    // =========================================================================
    public static class KmacTests
    {
        private static readonly byte[] Key = new byte[32];
        private static readonly byte[] Data = new byte[64];

        public static Kmac128 Kmac128Constructor() => new Kmac128(Key);
        public static byte[]  Kmac128OneShot()     => Kmac128.HashData(Key, Data, 32);
        public static byte[]  Kmac128Streaming(Kmac128 kmac)
        {
            kmac.AppendData(Data);
            return kmac.GetHashAndReset(32);
        }

        public static Kmac256 Kmac256Constructor() => new Kmac256(Key);
        public static byte[]  Kmac256OneShot()     => Kmac256.HashData(Key, Data, 64);

        public static KmacXof128 KmacXof128Constructor() => new KmacXof128(Key);
        public static byte[]     KmacXof128OneShot()     => KmacXof128.HashData(Key, Data, 32);

        public static KmacXof256 KmacXof256Constructor() => new KmacXof256(Key);
        public static byte[]     KmacXof256OneShot()     => KmacXof256.HashData(Key, Data, 64);
    }

    // =========================================================================
    // Password-based encryption parameters (PbeParameters / PbeEncryptionAlgorithm)
    // Expected algo tags: pbe-aes-256-cbc-sha256, pbe-3des-pkcs12-sha1, pbe-params
    // =========================================================================
    public static class PbeParametersTests
    {
        public static PbeParameters Aes256CbcSha256() =>
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000);

        public static PbeParameters TripleDesPkcs12Sha1() =>
            new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 100_000);

        public static PbeParameters Unresolvable(PbeEncryptionAlgorithm algorithm, HashAlgorithmName hash, int iterations) =>
            new PbeParameters(algorithm, hash, iterations);

        public static PbeParameters UnknownSha1() =>
            new PbeParameters(PbeEncryptionAlgorithm.Unknown, HashAlgorithmName.SHA1, 100_000);

        public static PbeParameters Aes128CbcSha256() =>
            new PbeParameters(PbeEncryptionAlgorithm.Aes128Cbc, HashAlgorithmName.SHA256, 600_000);

        public static PbeParameters Aes192CbcSha256() =>
            new PbeParameters(PbeEncryptionAlgorithm.Aes192Cbc, HashAlgorithmName.SHA256, 600_000);

        public static PbeParameters Aes256CbcSha1() =>
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA1, 600_000);

        public static PbeParameters Aes256CbcSha384() =>
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA384, 600_000);

        public static PbeParameters Aes256CbcSha512() =>
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 600_000);

        public static PbeParameters TripleDesPkcs12Sha256() =>
            new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA256, 100_000);

        public static PbeParameters TripleDesPkcs12Sha512() =>
            new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA512, 100_000);
    }

    // =========================================================================
    // NIST SP 800-108 counter-mode KDF (.NET 8+)
    // Expected algo tags: sp800-108-hmac-counter-sha256, sp800-108-hmac-counter
    // =========================================================================
    public static class PgpSp800108KdfTests
    {
        private static readonly byte[] Key = new byte[32];
        private static readonly byte[] Label = new byte[8];
        private static readonly byte[] Context = new byte[8];

        public static SP800108HmacCounterKdf ConstructWithSha256() =>
            new SP800108HmacCounterKdf(Key, HashAlgorithmName.SHA256);

        public static byte[] DeriveBytesOneShot() =>
            SP800108HmacCounterKdf.DeriveBytes(Key, HashAlgorithmName.SHA256, Label, Context, 32);

        public static byte[] DeriveKeyInstance(SP800108HmacCounterKdf kdf) =>
            kdf.DeriveKey(Label, Context, 32);

        public static SP800108HmacCounterKdf ConstructWithSha1() =>
            new SP800108HmacCounterKdf(Key, HashAlgorithmName.SHA1);

        public static SP800108HmacCounterKdf ConstructWithSha384() =>
            new SP800108HmacCounterKdf(Key, HashAlgorithmName.SHA384);

        public static SP800108HmacCounterKdf ConstructWithSha512() =>
            new SP800108HmacCounterKdf(Key, HashAlgorithmName.SHA512);
    }

}
