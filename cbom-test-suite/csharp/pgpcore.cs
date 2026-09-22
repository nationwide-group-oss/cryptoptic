// Test suite for PgpCore.ql
// Every method exercises at least one detection path in the QL query.
// type-stubs.cs provides PgpCore and Org.BouncyCastle.Bcpg declarations for
// the CodeQL extractor in --build-mode=none.

using System.IO;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg;
using PgpCore;

namespace CbomTestSuite.Csharp
{
    // =========================================================================
    // Key generation
    // Expected: pgp-keygen
    // =========================================================================
    public static class PgpKeyGenerationTests
    {
        // Sync key generation (file output)
        public static void GenerateRsaKey()
        {
            using var pgp = new PGP();
            pgp.GenerateKey(
                new FileInfo(@"/tmp/public.asc"),
                new FileInfo(@"/tmp/private.asc"),
                "user@example.com",
                "s3cret");
        }

        // Async key generation with explicit algorithm configuration
        public static async Task GenerateEd25519Key()
        {
            using var pgp = new PGP
            {
                PublicKeyAlgorithm = PublicKeyAlgorithmTag.EdDsa,
                HashAlgorithmTag   = HashAlgorithmTag.Sha256,
            };
            await pgp.GenerateKeyAsync(
                new FileInfo(@"/tmp/ed25519-public.asc"),
                new FileInfo(@"/tmp/ed25519-private.asc"),
                "user@example.com",
                "s3cret");
        }
    }

    // =========================================================================
    // Encryption
    // Expected: pgp-encrypt
    // =========================================================================
    public static class PgpEncryptTests
    {
        // File encrypt
        public static async Task EncryptFile(FileInfo inputFile, FileInfo outputFile)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/public.asc"));
            using var pgp = new PGP(keys)
            {
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Aes256,
            };
            await pgp.EncryptAsync(inputFile, outputFile);
        }

        // Stream encrypt
        public static async Task EncryptStream(Stream inputStream, Stream outputStream)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/public.asc"));
            using var pgp = new PGP(keys);
            await pgp.EncryptAsync(inputStream, outputStream);
        }

        // String encrypt
        public static async Task<string> EncryptString(string plaintext)
        {
            var keys = new EncryptionKeys(@"--- BEGIN PGP PUBLIC KEY BLOCK ---");
            using var pgp = new PGP(keys);
            return await pgp.EncryptAsync(plaintext);
        }

        // AES-128 (weaker cipher to exercise all SymmetricKeyAlgorithmTag values)
        public static async Task EncryptAes128(FileInfo inputFile, FileInfo outputFile)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/public.asc"));
            using var pgp = new PGP(keys) { SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Aes128 };
            await pgp.EncryptAsync(inputFile, outputFile);
        }

        // 3DES (legacy)
        public static async Task EncryptTripleDes(FileInfo inputFile, FileInfo outputFile)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/public.asc"));
            using var pgp = new PGP(keys) { SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.TripleDes };
            await pgp.EncryptAsync(inputFile, outputFile);
        }

        // Camellia-256
        public static async Task EncryptCamellia256(FileInfo inputFile, FileInfo outputFile)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/public.asc"));
            using var pgp = new PGP(keys) { SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Camellia256 };
            await pgp.EncryptAsync(inputFile, outputFile);
        }
    }

    // =========================================================================
    // Signing
    // Expected: pgp-sign
    // =========================================================================
    public static class PgpSignTests
    {
        public static async Task SignFile(FileInfo inputFile, FileInfo outputFile)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/private.asc"), "passphrase");
            using var pgp = new PGP(keys)
            {
                HashAlgorithmTag = HashAlgorithmTag.Sha512,
            };
            await pgp.SignAsync(inputFile, outputFile);
        }

        public static async Task SignStream(Stream inputStream, Stream outputStream)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/private.asc"), "passphrase");
            using var pgp = new PGP(keys);
            await pgp.SignAsync(inputStream, outputStream);
        }

        public static async Task<string> SignString(string input)
        {
            var keys = new EncryptionKeys(@"--- BEGIN PGP PRIVATE KEY BLOCK ---", "passphrase");
            using var pgp = new PGP(keys) { HashAlgorithmTag = HashAlgorithmTag.Sha256 };
            return await pgp.SignAsync(input);
        }
    }

    // =========================================================================
    // Clear signing
    // Expected: pgp-clear-sign
    // =========================================================================
    public static class PgpClearSignTests
    {
        public static async Task ClearSignFile(FileInfo inputFile, FileInfo outputFile)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/private.asc"), "passphrase");
            using var pgp = new PGP(keys);
            await pgp.ClearSignAsync(inputFile, outputFile);
        }

        public static async Task<string> ClearSignString(string input)
        {
            var keys = new EncryptionKeys(@"--- BEGIN PGP PRIVATE KEY BLOCK ---", "passphrase");
            using var pgp = new PGP(keys);
            return await pgp.ClearSignAsync(input);
        }
    }

    // =========================================================================
    // Detached signing and verification
    // Expected: pgp-sign-detached, pgp-verify-detached
    // =========================================================================
    public static class PgpDetachedSignTests
    {
        public static async Task SignDetachedFile(FileInfo inputFile, FileInfo signatureFile)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/private.asc"), "passphrase");
            using var pgp = new PGP(keys);
            await pgp.SignDetachedAsync(inputFile, signatureFile);
        }

        public static async Task<bool> VerifyDetachedFile(FileInfo inputFile, FileInfo signatureFile)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/public.asc"));
            using var pgp = new PGP(keys);
            return await pgp.VerifyDetachedAsync(inputFile, signatureFile);
        }

        public static async Task<bool> VerifyDetachedString(string content, string signature)
        {
            var keys = new EncryptionKeys(@"--- BEGIN PGP PUBLIC KEY BLOCK ---");
            using var pgp = new PGP(keys);
            return await pgp.VerifyDetachedAsync(content, signature);
        }
    }

    // =========================================================================
    // Encrypt and sign
    // Expected: pgp-encrypt-sign
    // =========================================================================
    public static class PgpEncryptAndSignTests
    {
        public static async Task EncryptAndSignFile(FileInfo inputFile, FileInfo outputFile)
        {
            var keys = new EncryptionKeys(
                new FileInfo(@"/tmp/recipient-public.asc"),
                new FileInfo(@"/tmp/sender-private.asc"),
                "passphrase");
            using var pgp = new PGP(keys);
            await pgp.EncryptAndSignAsync(inputFile, outputFile);
        }

        public static async Task<string> EncryptAndSignString(string plaintext)
        {
            var keys = new EncryptionKeys(
                @"--- BEGIN PGP PUBLIC KEY BLOCK ---",
                @"--- BEGIN PGP PRIVATE KEY BLOCK ---",
                "passphrase");
            using var pgp = new PGP(keys)
            {
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Aes256,
                HashAlgorithmTag      = HashAlgorithmTag.Sha256,
            };
            return await pgp.EncryptAndSignAsync(plaintext);
        }
    }

    // =========================================================================
    // Decryption
    // Expected: pgp-decrypt
    // =========================================================================
    public static class PgpDecryptTests
    {
        public static async Task DecryptFile(FileInfo inputFile, FileInfo outputFile)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/private.asc"), "passphrase");
            using var pgp = new PGP(keys);
            await pgp.DecryptAsync(inputFile, outputFile);
        }

        public static async Task<string> DecryptString(string ciphertext)
        {
            var keys = new EncryptionKeys(@"--- BEGIN PGP PRIVATE KEY BLOCK ---", "passphrase");
            using var pgp = new PGP(keys);
            return await pgp.DecryptAsync(ciphertext);
        }
    }

    // =========================================================================
    // Verification
    // Expected: pgp-verify
    // =========================================================================
    public static class PgpVerifyTests
    {
        public static async Task<bool> VerifyFile(FileInfo inputFile)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/public.asc"));
            using var pgp = new PGP(keys);
            return await pgp.VerifyAsync(inputFile);
        }

        public static async Task<bool> VerifyString(string signedContent)
        {
            var keys = new EncryptionKeys(@"--- BEGIN PGP PUBLIC KEY BLOCK ---");
            using var pgp = new PGP(keys);
            return await pgp.VerifyAsync(signedContent);
        }
    }

    // =========================================================================
    // Verify clear-signed
    // Expected: pgp-verify-clear
    // =========================================================================
    public static class PgpVerifyClearTests
    {
        public static async Task<bool> VerifyClearFile(FileInfo inputFile)
        {
            var keys = new EncryptionKeys(new FileInfo(@"/tmp/public.asc"));
            using var pgp = new PGP(keys);
            return await pgp.VerifyClearAsync(inputFile);
        }

        public static async Task<string> VerifyAndReadClearArmored(string signedMessage)
        {
            var keys = new EncryptionKeys(@"--- BEGIN PGP PUBLIC KEY BLOCK ---");
            using var pgp = new PGP(keys);
            return await pgp.VerifyAndReadClearArmoredStringAsync(signedMessage);
        }
    }

    // =========================================================================
    // Decrypt and verify
    // Expected: pgp-decrypt-verify
    // =========================================================================
    public static class PgpDecryptAndVerifyTests
    {
        public static async Task DecryptAndVerifyFile(FileInfo inputFile, FileInfo outputFile)
        {
            var keys = new EncryptionKeys(
                new FileInfo(@"/tmp/sender-public.asc"),
                new FileInfo(@"/tmp/private.asc"),
                "passphrase");
            using var pgp = new PGP(keys);
            await pgp.DecryptAndVerifyAsync(inputFile, outputFile);
        }

        public static async Task<string> DecryptAndVerifyString(string ciphertext)
        {
            var keys = new EncryptionKeys(
                @"--- BEGIN PGP PUBLIC KEY BLOCK ---",
                @"--- BEGIN PGP PRIVATE KEY BLOCK ---",
                "passphrase");
            using var pgp = new PGP(keys);
            return await pgp.DecryptAndVerifyAsync(ciphertext);
        }
    }

    // =========================================================================
    // Inspect
    // Expected: pgp-inspect
    // =========================================================================
    public static class PgpInspectTests
    {
        public static async Task<PgpInspectResult> InspectFile(FileInfo inputFile)
        {
            using var pgp = new PGP();
            return await pgp.InspectAsync(inputFile);
        }

        public static async Task<PgpInspectResult> InspectString(string pgpMessage)
        {
            using var pgp = new PGP();
            return await pgp.InspectAsync(pgpMessage);
        }
    }

    // =========================================================================
    // EncryptionKeysBuilder — fluent key loading for multi-key scenarios
    // (No direct detection; verifies stubs compile correctly)
    // =========================================================================
    public static class PgpKeyBuilderTests
    {
        public static async Task DecryptWithMultipleKeys(string ciphertext)
        {
            var keys = new EncryptionKeysBuilder()
                .WithPublicKey(new FileInfo(@"/tmp/sender-public.asc"))
                .WithPrivateKey(new FileInfo(@"/tmp/private1.asc"), "passphrase1")
                .WithPrivateKey(new FileInfo(@"/tmp/private2.asc"), "passphrase2")
                .Build();
            using var pgp = new PGP(keys);
            await pgp.DecryptAsync(ciphertext);
        }
    }

    // =========================================================================
    // Algorithm tag reference coverage
    // Exercises remaining SymmetricKeyAlgorithmTag, HashAlgorithmTag, and
    // PublicKeyAlgorithmTag values not yet used above.
    // Expected: various pgp-sym-*, sha*, rsa, dsa, ecdsa, ecdh, elgamal, ed25519
    // =========================================================================
    public static class PgpAlgorithmTagTests
    {
        // Remaining SymmetricKeyAlgorithmTag values
        public static SymmetricKeyAlgorithmTag GetCast5()       => SymmetricKeyAlgorithmTag.Cast5;
        public static SymmetricKeyAlgorithmTag GetBlowfish()    => SymmetricKeyAlgorithmTag.Blowfish;
        public static SymmetricKeyAlgorithmTag GetAes192()      => SymmetricKeyAlgorithmTag.Aes192;
        public static SymmetricKeyAlgorithmTag GetTwofish()     => SymmetricKeyAlgorithmTag.Twofish;
        public static SymmetricKeyAlgorithmTag GetCamellia128() => SymmetricKeyAlgorithmTag.Camellia128;
        public static SymmetricKeyAlgorithmTag GetCamellia192() => SymmetricKeyAlgorithmTag.Camellia192;
        public static SymmetricKeyAlgorithmTag GetDes()         => SymmetricKeyAlgorithmTag.Des;
        public static SymmetricKeyAlgorithmTag GetIdea()        => SymmetricKeyAlgorithmTag.Idea;
        public static SymmetricKeyAlgorithmTag GetSafer()       => SymmetricKeyAlgorithmTag.Safer;

        // Remaining HashAlgorithmTag values
        public static HashAlgorithmTag GetSha1()      => HashAlgorithmTag.Sha1;
        public static HashAlgorithmTag GetSha384()    => HashAlgorithmTag.Sha384;
        public static HashAlgorithmTag GetSha224()    => HashAlgorithmTag.Sha224;
        public static HashAlgorithmTag GetRipeMD160() => HashAlgorithmTag.RipeMD160;
        public static HashAlgorithmTag GetMd5()       => HashAlgorithmTag.MD5;
        public static HashAlgorithmTag GetDoubleSha() => HashAlgorithmTag.DoubleSha;
        public static HashAlgorithmTag GetTiger192()  => HashAlgorithmTag.Tiger192;

        // PublicKeyAlgorithmTag values
        public static async Task GenerateDsaKey()
        {
            using var pgp = new PGP { PublicKeyAlgorithm = PublicKeyAlgorithmTag.Dsa };
            await pgp.GenerateKeyAsync(
                new FileInfo(@"/tmp/dsa-public.asc"),
                new FileInfo(@"/tmp/dsa-private.asc"),
                "user@example.com", "s3cret");
        }

        public static async Task GenerateEcdsaKey()
        {
            using var pgp = new PGP { PublicKeyAlgorithm = PublicKeyAlgorithmTag.ECDsa };
            await pgp.GenerateKeyAsync(
                new FileInfo(@"/tmp/ecdsa-public.asc"),
                new FileInfo(@"/tmp/ecdsa-private.asc"),
                "user@example.com", "s3cret");
        }

        public static PublicKeyAlgorithmTag GetRsaGeneral()     => PublicKeyAlgorithmTag.RsaGeneral;
        public static PublicKeyAlgorithmTag GetRsaEncrypt()     => PublicKeyAlgorithmTag.RsaEncrypt;
        public static PublicKeyAlgorithmTag GetRsaSign()        => PublicKeyAlgorithmTag.RsaSign;
        public static PublicKeyAlgorithmTag GetElGamal()        => PublicKeyAlgorithmTag.ElGamalEncrypt;
        public static PublicKeyAlgorithmTag GetElGamalGeneral() => PublicKeyAlgorithmTag.ElGamalGeneral;
        public static PublicKeyAlgorithmTag GetEcdh()           => PublicKeyAlgorithmTag.ECDH;
        public static PublicKeyAlgorithmTag GetDiffieHellman()  => PublicKeyAlgorithmTag.DiffieHellman;
    }

    // =========================================================================
    // AeadAlgorithmTag — OpenPGP v5/v6 AEAD modes
    // Expected algo tags: pgp-aead-eax, pgp-aead-ocb, pgp-aead-gcm
    // =========================================================================
    public static class PgpAeadTests
    {
        public static AeadAlgorithmTag Eax() => AeadAlgorithmTag.Eax;
        public static AeadAlgorithmTag Ocb() => AeadAlgorithmTag.Ocb;
        public static AeadAlgorithmTag Gcm() => AeadAlgorithmTag.Gcm;
    }

    // =========================================================================
    // Modern PublicKeyAlgorithmTag values
    // Expected algo tags: eddsa, ed25519, ed448, x25519, x448
    // =========================================================================
    public static class PgpModernKeyAlgoTests
    {
        public static PublicKeyAlgorithmTag EdDsaLegacy() => PublicKeyAlgorithmTag.EdDsa_Legacy;
        public static PublicKeyAlgorithmTag Ed25519()     => PublicKeyAlgorithmTag.Ed25519;
        public static PublicKeyAlgorithmTag Ed448()       => PublicKeyAlgorithmTag.Ed448;
        public static PublicKeyAlgorithmTag X25519()      => PublicKeyAlgorithmTag.X25519;
        public static PublicKeyAlgorithmTag X448()        => PublicKeyAlgorithmTag.X448;
    }

    // =========================================================================
    // Remaining PGP algorithm tags and operations
    // Expected algo tags: md2, pgp-sym-null, pgp-get-recipients
    // =========================================================================
    public static class PgpRemainingTests
    {
        public static HashAlgorithmTag Md2()             => HashAlgorithmTag.MD2;
        // MD4 = 301 is [Obsolete("Non-standard")] but still a real BC member.
        public static HashAlgorithmTag Md4()             => HashAlgorithmTag.MD4;
        public static SymmetricKeyAlgorithmTag NullSym() => SymmetricKeyAlgorithmTag.Null;

        public static System.Collections.Generic.IEnumerable<long> Recipients(string input) =>
            new PGP().GetRecipients(input);
    }

    // =========================================================================
    // Remaining hash and compression algorithm tags
    // Expected algo tags: haval5pass160, sha3-224, sha3-256, sha3-384,
    //   sha3-512, sha3-256-old, sha3-512-old, sm3,
    //   pgp-compression-none, pgp-compression-zip, pgp-compression-zlib,
    //   pgp-compression-bzip2
    // =========================================================================
    public static class PgpAdditionalAlgorithmTagTests
    {
        public static HashAlgorithmTag Haval5pass160() => HashAlgorithmTag.Haval5pass160;
        public static HashAlgorithmTag Sha3_224()      => HashAlgorithmTag.Sha3_224;
        public static HashAlgorithmTag Sha3_256()      => HashAlgorithmTag.Sha3_256;
        public static HashAlgorithmTag Sha3_384()      => HashAlgorithmTag.Sha3_384;
        public static HashAlgorithmTag Sha3_512()      => HashAlgorithmTag.Sha3_512;
        public static HashAlgorithmTag Sha3_256_Old()  => HashAlgorithmTag.Sha3_256_Old;
        public static HashAlgorithmTag Sha3_512_Old()  => HashAlgorithmTag.Sha3_512_Old;
        public static HashAlgorithmTag Sm3()            => HashAlgorithmTag.SM3;

        public static CompressionAlgorithmTag Uncompressed() => CompressionAlgorithmTag.Uncompressed;
        public static CompressionAlgorithmTag Zip()         => CompressionAlgorithmTag.Zip;
        public static CompressionAlgorithmTag ZLib()        => CompressionAlgorithmTag.ZLib;
        public static CompressionAlgorithmTag BZip2()       => CompressionAlgorithmTag.BZip2;
    }

}
