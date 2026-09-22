// Test suite for MicrosoftBclCryptography.ql
// Every method exercises at least one detection path in the QL query.
// type-stubs.cs provides MLDsa, MLKem, SlhDsa, CompositeMLDsa declarations.
// SP800108HmacCounterKdf is in the .NET 8 BCL and needs no stub.

using System;
using System.Security.Cryptography;

namespace CbomTestSuite.Csharp
{
    // =========================================================================
    // ML-DSA (FIPS 204) — key generation, import, signing, verification
    // Expected: ml-dsa-44/65/87 (keygen + imports), ml-dsa (PEM/PKCS8 imports),
    //           ml-dsa-sign, ml-dsa-verify, standalone property reads
    // =========================================================================
    public static class MlDsaTests
    {
        // Key generation with resolved algorithm
        public static MLDsa GenerateMlDsa44Key()
            => MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);

        public static MLDsa GenerateMlDsa65Key()
            => MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);

        public static MLDsa GenerateMlDsa87Key()
            => MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87);

        // Key generation with algorithm via local variable (data flow path)
        public static MLDsa GenerateMlDsaKeyViaVariable()
        {
            var algo = MLDsaAlgorithm.MLDsa65;
            return MLDsa.GenerateKey(algo);
        }

        // Import raw key bytes with algorithm
        public static MLDsa ImportPublicKey(byte[] spki)
            => MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa44, spki);

        public static MLDsa ImportPrivateKey(byte[] privKey)
            => MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm.MLDsa65, privKey);

        public static MLDsa ImportPrivateSeed(byte[] seed)
            => MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa87, seed);

        // Import via standard formats (algorithm variant not statically known)
        public static MLDsa ImportFromSpki(byte[] spki)
            => MLDsa.ImportSubjectPublicKeyInfo(spki);

        public static MLDsa ImportFromPkcs8(byte[] pkcs8)
            => MLDsa.ImportPkcs8PrivateKey(pkcs8);

        public static MLDsa ImportFromPem(string pem)
            => MLDsa.ImportFromPem(pem);

        // Signing and verification
        public static byte[] Sign(MLDsa key, byte[] data)
            => key.SignData(data);

        public static byte[] SignWithContext(MLDsa key, byte[] data, byte[] context)
            => key.SignData(data, context);

        public static byte[] SignPreHash(MLDsa key, byte[] hash, string oid)
            => key.SignPreHash(hash, oid);

        public static byte[] SignMu(MLDsa key, byte[] mu)
            => key.SignMu(mu);

        public static bool Verify(MLDsa key, byte[] data, byte[] sig)
            => key.VerifyData(data, sig);

        public static bool VerifyPreHash(MLDsa key, byte[] hash, byte[] sig, string oid)
            => key.VerifyPreHash(hash, sig, oid);

        public static bool VerifyMu(MLDsa key, byte[] mu, byte[] sig)
            => key.VerifyMu(mu, sig);

        // Standalone algorithm identifier property reads
        public static MLDsaAlgorithm GetAlgo44()  => MLDsaAlgorithm.MLDsa44;
        public static MLDsaAlgorithm GetAlgo65()  => MLDsaAlgorithm.MLDsa65;
        public static MLDsaAlgorithm GetAlgo87()  => MLDsaAlgorithm.MLDsa87;

        // Key export
        public static byte[] ExportPublicKey(MLDsa key)       => key.ExportMLDsaPublicKey();
        public static byte[] ExportPrivateKey(MLDsa key)      => key.ExportMLDsaPrivateKey();
        public static byte[] ExportPrivateSeed(MLDsa key)     => key.ExportMLDsaPrivateSeed();
        public static byte[] ExportSpki(MLDsa key)            => key.ExportSubjectPublicKeyInfo();
        public static byte[] ExportPkcs8(MLDsa key)           => key.ExportPkcs8PrivateKey();
        public static bool TryExportPublicKey(MLDsa key, Span<byte> dest) => key.TryExportMLDsaPublicKey(dest, out _);

        // Encrypted / PEM import and export
        public static MLDsa ImportEncryptedPkcs8(byte[] pkcs8, byte[] password)
            => MLDsa.ImportEncryptedPkcs8PrivateKey(password, pkcs8);

        public static MLDsa ImportFromEncryptedPem(string pem, string password)
            => MLDsa.ImportFromEncryptedPem(pem, password);

        public static string ExportSpkiPem(MLDsa key)         => key.ExportSubjectPublicKeyInfoPem();
        public static string ExportPkcs8Pem(MLDsa key)        => key.ExportPkcs8PrivateKeyPem();
        public static byte[] ExportEncryptedPkcs8(MLDsa key, string password, PbeParameters pbe)
            => key.ExportEncryptedPkcs8PrivateKey(password, pbe);
        public static string ExportEncryptedPkcs8Pem(MLDsa key, string password, PbeParameters pbe)
            => key.ExportEncryptedPkcs8PrivateKeyPem(password, pbe);
    }

    // =========================================================================
    // ML-KEM (FIPS 203) — key generation, encapsulation, decapsulation
    // Expected: ml-kem-512/768/1024, ml-kem-encapsulate, ml-kem-decapsulate
    // =========================================================================
    public static class MlKemTests
    {
        public static MLKem GenerateMlKem512()
            => MLKem.GenerateKey(MLKemAlgorithm.MLKem512);

        public static MLKem GenerateMlKem768()
            => MLKem.GenerateKey(MLKemAlgorithm.MLKem768);

        public static MLKem GenerateMlKem1024()
            => MLKem.GenerateKey(MLKemAlgorithm.MLKem1024);

        // Key generation via variable (data flow path)
        public static MLKem GenerateViaSizeVariable()
        {
            var algo = MLKemAlgorithm.MLKem768;
            return MLKem.GenerateKey(algo);
        }

        // Import encapsulation (public) key
        public static MLKem ImportEncapKey(byte[] ekBytes)
            => MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, ekBytes);

        // Import decapsulation (private) key
        public static MLKem ImportDecapKey(byte[] dkBytes)
            => MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem1024, dkBytes);

        // Import from a private seed
        public static MLKem ImportPrivateSeed(byte[] seed)
            => MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, seed);

        // Import from standard formats
        public static MLKem ImportFromSpki(byte[] spki)
            => MLKem.ImportSubjectPublicKeyInfo(spki);

        public static MLKem ImportFromPkcs8(byte[] pkcs8)
            => MLKem.ImportPkcs8PrivateKey(pkcs8);

        // Encapsulation (sender side — produces ciphertext + shared secret)
        public static void Encapsulate(MLKem key)
        {
            key.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret);
        }

        // Decapsulation (recipient side — recovers shared secret)
        public static byte[] Decapsulate(MLKem key, byte[] ciphertext)
            => key.Decapsulate(ciphertext);

        // Standalone property reads
        public static MLKemAlgorithm GetAlgo512()  => MLKemAlgorithm.MLKem512;
        public static MLKemAlgorithm GetAlgo768()  => MLKemAlgorithm.MLKem768;
        public static MLKemAlgorithm GetAlgo1024() => MLKemAlgorithm.MLKem1024;

        // Key export
        public static byte[] ExportEncapKey(MLKem key)        => key.ExportEncapsulationKey();
        public static byte[] ExportDecapKey(MLKem key)        => key.ExportDecapsulationKey();
        public static byte[] ExportSpki(MLKem key)            => key.ExportSubjectPublicKeyInfo();
        public static byte[] ExportPkcs8(MLKem key)           => key.ExportPkcs8PrivateKey();
        public static bool TryExportEncapKey(MLKem key, Span<byte> dest) => key.TryExportEncapsulationKey(dest, out _);
        public static bool TryExportDecapKey(MLKem key, Span<byte> dest) => key.TryExportDecapsulationKey(dest, out _);

        // Private-seed export (distinct key material, previously undetected)
        public static byte[] ExportPrivateSeed(MLKem key)     => key.ExportPrivateSeed();
        public static bool TryExportPrivateSeed(MLKem key, Span<byte> dest) => key.TryExportPrivateSeed(dest, out _);

        // Encrypted / PEM import and export
        public static MLKem ImportEncryptedPkcs8(byte[] pkcs8, byte[] password)
            => MLKem.ImportEncryptedPkcs8PrivateKey(password, pkcs8);

        public static MLKem ImportFromEncryptedPem(string pem, string password)
            => MLKem.ImportFromEncryptedPem(pem, password);

        public static string ExportSpkiPem(MLKem key)         => key.ExportSubjectPublicKeyInfoPem();
        public static string ExportPkcs8Pem(MLKem key)        => key.ExportPkcs8PrivateKeyPem();
        public static byte[] ExportEncryptedPkcs8(MLKem key, string password, PbeParameters pbe)
            => key.ExportEncryptedPkcs8PrivateKey(password, pbe);
    }

    // =========================================================================
    // SLH-DSA (FIPS 205) — key generation, signing, verification
    // Expected: slh-dsa-sha2-128s…slh-dsa-shake-256f, slh-dsa-sign, slh-dsa-verify
    // =========================================================================
    public static class SlhDsaTests
    {
        // SHA-2 parameter sets — small (security-focused)
        public static SlhDsa GenerateSha2_128s() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
        public static SlhDsa GenerateSha2_128f() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128f);
        public static SlhDsa GenerateSha2_192s() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_192s);
        public static SlhDsa GenerateSha2_192f() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_192f);
        public static SlhDsa GenerateSha2_256s() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_256s);
        public static SlhDsa GenerateSha2_256f() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_256f);

        // SHAKE parameter sets
        public static SlhDsa GenerateShake128s() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake128s);
        public static SlhDsa GenerateShake128f() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake128f);
        public static SlhDsa GenerateShake192s() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake192s);
        public static SlhDsa GenerateShake192f() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake192f);
        public static SlhDsa GenerateShake256s() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake256s);
        public static SlhDsa GenerateShake256f() => SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake256f);

        // Key generation via variable (data flow path)
        public static SlhDsa GenerateViaSizeVariable()
        {
            var algo = SlhDsaAlgorithm.SlhDsaSha2_128s;
            return SlhDsa.GenerateKey(algo);
        }

        // Import raw key bytes
        public static SlhDsa ImportPublicKey(byte[] pubKey)
            => SlhDsa.ImportSlhDsaPublicKey(SlhDsaAlgorithm.SlhDsaSha2_128s, pubKey);

        public static SlhDsa ImportPrivateKey(byte[] privKey)
            => SlhDsa.ImportSlhDsaPrivateKey(SlhDsaAlgorithm.SlhDsaShake256f, privKey);

        // Import from standard formats
        public static SlhDsa ImportFromSpki(byte[] spki)
            => SlhDsa.ImportSubjectPublicKeyInfo(spki);

        public static SlhDsa ImportFromPkcs8(byte[] pkcs8)
            => SlhDsa.ImportPkcs8PrivateKey(pkcs8);

        // Signing and verification
        public static byte[] Sign(SlhDsa key, byte[] data)
            => key.SignData(data);

        public static byte[] SignPreHash(SlhDsa key, byte[] hash, string oid)
            => key.SignPreHash(hash, oid);

        public static bool Verify(SlhDsa key, byte[] data, byte[] sig)
            => key.VerifyData(data, sig);

        public static bool VerifyPreHash(SlhDsa key, byte[] hash, byte[] sig, string oid)
            => key.VerifyPreHash(hash, sig, oid);

        // Standalone property reads
        public static SlhDsaAlgorithm GetSha2_128s() => SlhDsaAlgorithm.SlhDsaSha2_128s;
        public static SlhDsaAlgorithm GetShake256f() => SlhDsaAlgorithm.SlhDsaShake256f;

        // Key export
        public static byte[] ExportPublicKey(SlhDsa key)   => key.ExportSlhDsaPublicKey();
        public static byte[] ExportPrivateKey(SlhDsa key)  => key.ExportSlhDsaPrivateKey();
        public static byte[] ExportSpki(SlhDsa key)        => key.ExportSubjectPublicKeyInfo();
        public static byte[] ExportPkcs8(SlhDsa key)       => key.ExportPkcs8PrivateKey();
        public static bool TryExportPublicKey(SlhDsa key, Span<byte> dest) => key.TryExportSlhDsaPublicKey(dest, out _);

        // Encrypted / PEM import and export
        public static SlhDsa ImportEncryptedPkcs8(byte[] pkcs8, byte[] password)
            => SlhDsa.ImportEncryptedPkcs8PrivateKey(password, pkcs8);

        public static SlhDsa ImportFromEncryptedPem(string pem, string password)
            => SlhDsa.ImportFromEncryptedPem(pem, password);

        public static string ExportSpkiPem(SlhDsa key)      => key.ExportSubjectPublicKeyInfoPem();
        public static string ExportPkcs8Pem(SlhDsa key)     => key.ExportPkcs8PrivateKeyPem();
        public static byte[] ExportEncryptedPkcs8(SlhDsa key, string password, PbeParameters pbe)
            => key.ExportEncryptedPkcs8PrivateKey(password, pbe);
    }

    // =========================================================================
    // Composite ML-DSA — ML-DSA combined with a classical algorithm
    // Expected: composite-ml-dsa-keygen, composite-ml-dsa-sign, composite-ml-dsa-verify
    // =========================================================================
    public static class CompositeMlDsaTests
    {
        public static CompositeMLDsa GenerateKey()
            => CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa65WithEcdsaP256);

        public static CompositeMLDsa ImportFromSpki(byte[] spki)
            => CompositeMLDsa.ImportSubjectPublicKeyInfo(spki);

        public static CompositeMLDsa ImportFromPkcs8(byte[] pkcs8)
            => CompositeMLDsa.ImportPkcs8PrivateKey(pkcs8);

        public static CompositeMLDsa ImportFromPem(string pem)
            => CompositeMLDsa.ImportFromPem(pem);

        public static byte[] Sign(CompositeMLDsa key, byte[] data)
            => key.SignData(data);

        public static bool Verify(CompositeMLDsa key, byte[] data, byte[] sig)
            => key.VerifyData(data, sig);

        // Standalone algorithm property reads
        public static CompositeMLDsaAlgorithm GetMlDsa44WithEd25519()
            => CompositeMLDsaAlgorithm.MLDsa44WithEd25519;

        public static CompositeMLDsaAlgorithm GetMlDsa65WithRsa()
            => CompositeMLDsaAlgorithm.MLDsa65WithRsa2048;

        public static CompositeMLDsaAlgorithm GetMlDsa87WithEcdsaP384()
            => CompositeMLDsaAlgorithm.MLDsa87WithEcdsaP384;

        // Composite-specific key import/export (previously entirely undetected)
        public static CompositeMLDsa ImportCompositePrivateKey(byte[] key)
            => CompositeMLDsa.ImportCompositeMLDsaPrivateKey(CompositeMLDsaAlgorithm.MLDsa65WithEcdsaP256, key);

        public static CompositeMLDsa ImportCompositePublicKey(byte[] key)
            => CompositeMLDsa.ImportCompositeMLDsaPublicKey(CompositeMLDsaAlgorithm.MLDsa65WithEcdsaP256, key);

        public static CompositeMLDsa ImportEncryptedPkcs8(byte[] pkcs8, byte[] password)
            => CompositeMLDsa.ImportEncryptedPkcs8PrivateKey(password, pkcs8);

        public static CompositeMLDsa ImportFromEncryptedPem(string pem, string password)
            => CompositeMLDsa.ImportFromEncryptedPem(pem, password);

        public static byte[] ExportCompositePrivateKey(CompositeMLDsa key) => key.ExportCompositeMLDsaPrivateKey();
        public static byte[] ExportCompositePublicKey(CompositeMLDsa key)  => key.ExportCompositeMLDsaPublicKey();
        public static byte[] ExportSpki(CompositeMLDsa key)                => key.ExportSubjectPublicKeyInfo();
        public static byte[] ExportPkcs8(CompositeMLDsa key)               => key.ExportPkcs8PrivateKey();
        public static string ExportSpkiPem(CompositeMLDsa key)             => key.ExportSubjectPublicKeyInfoPem();
        public static string ExportPkcs8Pem(CompositeMLDsa key)           => key.ExportPkcs8PrivateKeyPem();
        public static byte[] ExportEncryptedPkcs8(CompositeMLDsa key, string password, PbeParameters pbe)
            => key.ExportEncryptedPkcs8PrivateKey(password, pbe);
    }

    // =========================================================================
    // SP 800-108 HMAC Counter-mode KDF (in .NET 8 BCL — no stub needed)
    // Expected: sp800-108-hmac-{hash}, sp800-108-hmac-derive
    // =========================================================================
    public static class Sp800108KdfTests
    {
        // Constructor with each supported hash — algo resolved at construction time
        public static byte[] DeriveWithSha256(byte[] key, byte[] label, byte[] context)
        {
            using var kdf = new SP800108HmacCounterKdf(key, HashAlgorithmName.SHA256);
            return kdf.DeriveKey(label, context, 32);
        }

        public static byte[] DeriveWithSha384(byte[] key, byte[] label, byte[] context)
        {
            using var kdf = new SP800108HmacCounterKdf(key, HashAlgorithmName.SHA384);
            return kdf.DeriveKey(label, context, 48);
        }

        public static byte[] DeriveWithSha512(byte[] key, byte[] label, byte[] context)
        {
            using var kdf = new SP800108HmacCounterKdf(key, HashAlgorithmName.SHA512);
            return kdf.DeriveKey(label, context, 64);
        }

        public static byte[] DeriveWithSha3_256(byte[] key, byte[] label, byte[] context)
        {
            using var kdf = new SP800108HmacCounterKdf(key, HashAlgorithmName.SHA3_256);
            return kdf.DeriveKey(label, context, 32);
        }

        public static byte[] DeriveWithSha3_384(byte[] key, byte[] label, byte[] context)
        {
            using var kdf = new SP800108HmacCounterKdf(key, HashAlgorithmName.SHA3_384);
            return kdf.DeriveKey(label, context, 48);
        }

        public static byte[] DeriveWithSha3_512(byte[] key, byte[] label, byte[] context)
        {
            using var kdf = new SP800108HmacCounterKdf(key, HashAlgorithmName.SHA3_512);
            return kdf.DeriveKey(label, context, 64);
        }

        public static byte[] DeriveWithSha1(byte[] key, byte[] label, byte[] context)
        {
            using var kdf = new SP800108HmacCounterKdf(key, HashAlgorithmName.SHA1);
            return kdf.DeriveKey(label, context, 20);
        }

        public static byte[] DeriveWithMd5(byte[] key, byte[] label, byte[] context)
        {
            using var kdf = new SP800108HmacCounterKdf(key, HashAlgorithmName.MD5);
            return kdf.DeriveKey(label, context, 16);
        }

        // DeriveBytes overload — same KDF, different output format
        public static byte[] DeriveBytesWithSha256(byte[] key, byte[] label, byte[] context)
        {
            using var kdf = new SP800108HmacCounterKdf(key, HashAlgorithmName.SHA256);
            return kdf.DeriveBytes(label, context, 32);
        }

        // Hash algorithm via variable (data flow path)
        public static byte[] DeriveViaVariable(byte[] key, byte[] label, byte[] context)
        {
            var hash = HashAlgorithmName.SHA512;
            using var kdf = new SP800108HmacCounterKdf(key, hash);
            return kdf.DeriveKey(label, context, 32);
        }

        // Unknown hash — fallback sp800-108-hmac-kdf
        public static byte[] DeriveUnknownHash(byte[] key, HashAlgorithmName hashName, byte[] label, byte[] context)
        {
            using var kdf = new SP800108HmacCounterKdf(key, hashName);
            return kdf.DeriveKey(label, context, 32);
        }

        // Static one-shot DeriveBytes — hash resolved from its own argument, not the constructor
        public static byte[] DeriveBytesStaticWithSha256(byte[] key, byte[] label, byte[] context)
            => SP800108HmacCounterKdf.DeriveBytes(key, HashAlgorithmName.SHA256, label, context, 32);

        public static byte[] DeriveBytesStaticUnknownHash(byte[] key, HashAlgorithmName hashName, byte[] label, byte[] context)
            => SP800108HmacCounterKdf.DeriveBytes(key, hashName, label, context, 32);
    }
}
