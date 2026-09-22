// Test suite for BouncyCastle.ql
// Every method exercises at least one detection path in the QL query.
// Includes both direct-instantiation patterns (bcDigestArgDirect) and
// variable-based patterns (DataFlow::localFlow) for key argument helpers.

using System.IO;
using Org.BouncyCastle.Asn1.Anssi;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Fpe;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pqc.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;

namespace CbomTestSuite.Csharp
{
    // =========================================================================
    // Hash Digests
    // Covers: all fixed-name digests, parameterised digests (Sha3, Keccak, Shake,
    //         CShake), SkeinDigest, DigestUtilities.GetDigest factory.
    // Expected algo tags: sha1, sha224, sha256, sha384, sha512, md2, md4, md5,
    //   ripemd128-320, whirlpool, tiger, sm3, gost3411, streebog-256/512,
    //   blake2b, blake2s, blake3, null-digest, sha3-256, sha3-512, keccak-256,
    //   shake-128, shake-256, cshake-128, skein-256-256, digest:sha-256,
    //   sha512t-224, sha512t-256
    // =========================================================================
    public static class BcHashingTests
    {
        // Fixed-name digest constructors
        public static IDigest Sha1()        => new Sha1Digest();
        public static IDigest Sha224()      => new Sha224Digest();
        public static IDigest Sha256()      => new Sha256Digest();
        public static IDigest Sha384()      => new Sha384Digest();
        public static IDigest Sha512()      => new Sha512Digest();
        public static IDigest MD2()         => new MD2Digest();
        public static IDigest MD4()         => new MD4Digest();
        public static IDigest MD5()         => new MD5Digest();
        public static IDigest RipeMD128()   => new RipeMD128Digest();
        public static IDigest RipeMD160()   => new RipeMD160Digest();
        public static IDigest RipeMD256()   => new RipeMD256Digest();
        public static IDigest RipeMD320()   => new RipeMD320Digest();
        public static IDigest Whirlpool()   => new WhirlpoolDigest();
        public static IDigest Tiger()       => new TigerDigest();
        public static IDigest SM3()         => new SM3Digest();
        public static IDigest Gost3411()    => new GOST3411Digest();
        public static IDigest Streebog256() => new GOST3411_2012_256Digest();
        public static IDigest Streebog512() => new GOST3411_2012_512Digest();
        public static IDigest Blake2b()     => new Blake2bDigest(512);
        public static IDigest Blake2s()     => new Blake2sDigest(256);
        public static IDigest Blake3()      => new Blake3Digest();
        public static IDigest NullHash()    => new NullDigest();

        // Parameterised digests — exercises bit-size literal extraction
        public static IDigest Sha3_256()   => new Sha3Digest(256);
        public static IDigest Sha3_512()   => new Sha3Digest(512);
        public static IDigest Keccak256()  => new KeccakDigest(256);
        public static IDigest Keccak512()  => new KeccakDigest(512);
        public static IDigest Shake128()   => new ShakeDigest(128);
        public static IDigest Shake256()   => new ShakeDigest(256);
        public static IDigest Skein256()   => new SkeinDigest(256, 256);
        public static IDigest Skein512()   => new SkeinDigest(512, 512);

        // FIPS 180-4 SHA-512/t truncated variants (distinct BC class from Sha512Digest)
        public static IDigest Sha512_224() => new Sha512tDigest(224);
        public static IDigest Sha512_256() => new Sha512tDigest(256);

        public static void CShake128()
        {
            _ = new CShakeDigest(128, null, null);
        }

        // String-based factory — exercises DigestUtilities.GetDigest
        public static IDigest ViaStringSha256()  => DigestUtilities.GetDigest("SHA-256");
        public static IDigest ViaStringSha3()    => DigestUtilities.GetDigest("SHA3-256");

        // Variable-based — exercises DataFlow::localFlow path in bcDigestArg
        public static IMac HmacViaSha256Variable()
        {
            var digest = new Sha256Digest();   // bcDigestArgDirect holds for `digest`
            var hmac = new HMac(digest);       // DataFlow tracks digest → hmac argument
            return hmac;
        }
    }

    // =========================================================================
    // MACs
    // Covers: HMac (with various digests), CMac, Poly1305, GMac,
    //         CBCBlockCipherMac, CFBBlockCipherMac, ISO9797Alg3Mac, SipHash,
    //         MacUtilities.GetMac factory.
    // Expected algo tags: hmac-sha256, hmac-md5, hmac-sha3-256,
    //   aes-cmac, aes-poly1305, aes-gmac, aes-cbc-mac, aes-cfb-mac,
    //   iso9797-alg3-mac, siphash, mac:hmacsha256
    // =========================================================================
    public static class BcMacTests
    {
        // HMac — direct digest argument
        public static IMac HmacSha256Direct()   => new HMac(new Sha256Digest());
        public static IMac HmacSha512Direct()   => new HMac(new Sha512Digest());
        public static IMac HmacMd5Direct()      => new HMac(new MD5Digest());
        public static IMac HmacSha3_256()       => new HMac(new Sha3Digest(256));
        public static IMac HmacRipeMD160()      => new HMac(new RipeMD160Digest());

        // HMac — variable-based argument (data-flow path)
        public static IMac HmacSha384Variable()
        {
            var d = new Sha384Digest();
            return new HMac(d);
        }

        // CMac
        public static IMac CmacAesDirect()     => new CMac(new AesEngine());
        public static IMac CmacDesEde()        => new CMac(new DesEdeEngine());

        // CMac — variable-based argument
        public static IMac CmacAesVariable()
        {
            var engine = new AesEngine();
            return new CMac(engine);
        }

        // Poly1305
        public static IMac Poly1305AesDirect() => new Poly1305(new AesEngine());

        // GMac
        public static void GMacAes()
        {
            _ = new GMac(new GcmBlockCipher(new AesEngine()));
        }

        // CBCBlockCipherMac / CFBBlockCipherMac
        public static IMac CbcMacAes() => new CBCBlockCipherMac(new AesEngine());
        public static IMac CfbMacAes() => new CFBBlockCipherMac(new AesEngine(), 8);

        // ISO9797Alg3Mac
        public static IMac Iso9797Alg3() => new ISO9797Alg3Mac(new DesEdeEngine());

        // SipHash
        public static IMac SipHash()     => new SipHash();
        public static IMac SipHash128()  => new SipHash128();

        // String-based factory
        public static IMac ViaStringHmac() => MacUtilities.GetMac("HMACSHA256");
        public static IMac ViaStringCmac() => MacUtilities.GetMac("AESCMAC");
    }

    // =========================================================================
    // Symmetric Ciphers — Block Cipher Engines
    // Covers: all bcCipherEngineName entries plus GeneratorUtilities.GetKeyGenerator.
    // Expected algo tags: aes, des, 3des, blowfish, twofish, camellia, rc2, rc6,
    //   cast5, cast6, serpent, skipjack, tea, xtea, sm4, aria, gost28147, idea,
    //   seed, noekeon, threefish, null-cipher, keygen:aes
    // =========================================================================
    public static class BcBlockCipherEngineTests
    {
        public static IBlockCipher Aes()         => new AesEngine();
        public static IBlockCipher AesLight()    => new AesLightEngine();
        public static IBlockCipher Des()         => new DesEngine();
        public static IBlockCipher DesEde()      => new DesEdeEngine();
        public static IBlockCipher Blowfish()    => new BlowfishEngine();
        public static IBlockCipher Twofish()     => new TwofishEngine();
        public static IBlockCipher Camellia()    => new CamelliaEngine();
        public static IBlockCipher CamelliaLight() => new CamelliaLightEngine();
        public static IBlockCipher Rc2()         => new Rc2Engine();
        public static IBlockCipher Rc6()         => new Rc6Engine();
        public static IBlockCipher Cast5()       => new Cast5Engine();
        public static IBlockCipher Cast6()       => new Cast6Engine();
        public static IBlockCipher Serpent()     => new SerpentEngine();
        public static IBlockCipher SerpentLight() => new SerpentLightEngine();
        public static IBlockCipher Skipjack()    => new SkipjackEngine();
        public static IBlockCipher Tea()         => new TeaEngine();
        public static IBlockCipher Xtea()        => new XteaEngine();
        public static IBlockCipher SM4()         => new SM4Engine();
        public static IBlockCipher Aria()        => new AriaEngine();
        public static IBlockCipher Gost28147()   => new Gost28147Engine();
        public static IBlockCipher Idea()        => new IdeaEngine();
        public static IBlockCipher Seed()        => new SeedEngine();
        public static IBlockCipher Noekeon()     => new NoekeonEngine();
        public static IBlockCipher Threefish()   => new ThreefishEngine(256);
        public static IBlockCipher NullCipher()  => new NullEngine();

        // String-based key generator factory
        public static void KeyGenAes()  { _ = GeneratorUtilities.GetKeyGenerator("AES"); }
        public static void KeyGenDes3() { _ = GeneratorUtilities.GetKeyGenerator("DESEDE"); }
    }

    // =========================================================================
    // Symmetric Ciphers — Block Cipher Modes and AEAD
    // Covers: GcmBlockCipher, CcmBlockCipher, EaxBlockCipher, OcbBlockCipher,
    //         CbcBlockCipher, CfbBlockCipher, OfbBlockCipher, SicBlockCipher,
    //         GofbBlockCipher, CtsBlockCipher, ChaCha20Poly1305,
    //         CipherUtilities.GetCipher factory.
    // Expected algo tags: aes-gcm, aes-ccm, aes-eax, aes-ocb, aes-cbc, aes-cfb,
    //   aes-ofb, aes-ctr, aes-gofb, aes-cts, 3des-cbc, chacha20-poly1305,
    //   cipher:aes/cbc/pkcs7padding, cipher:aes/gcm/nopadding
    // =========================================================================
    public static class BcBlockCipherModeTests
    {
        // AEAD modes — direct engine argument
        public static IAeadBlockCipher AesGcmDirect()  => new GcmBlockCipher(new AesEngine());
        public static IAeadBlockCipher AesCcmDirect()  => new CcmBlockCipher(new AesEngine());
        public static IAeadBlockCipher AesEaxDirect()  => new EaxBlockCipher(new AesEngine());
        public static IAeadBlockCipher AesOcbDirect()  => new OcbBlockCipher(new AesEngine(), new AesEngine());

        // AEAD modes — variable-based engine argument (data-flow path)
        public static IAeadBlockCipher AesGcmVariable()
        {
            var engine = new AesEngine();
            return new GcmBlockCipher(engine);
        }

        // Classical modes — direct engine argument
        public static IBlockCipher AesCbcDirect()     => new CbcBlockCipher(new AesEngine());
        public static IBlockCipher AesCfbDirect()     => new CfbBlockCipher(new AesEngine(), 128);
        public static IBlockCipher AesOfbDirect()     => new OfbBlockCipher(new AesEngine(), 128);
        public static IBlockCipher AesCtrDirect()     => new SicBlockCipher(new AesEngine());
        public static IBlockCipher AesGofbDirect()    => new GofbBlockCipher(new AesEngine());
        public static IBlockCipher AesCtsDirect()     => new CtsBlockCipher(new CbcBlockCipher(new AesEngine()));

        // Classical modes — variable engine (data-flow path)
        public static IBlockCipher AesCbcVariable()
        {
            var engine = new AesEngine();
            return new CbcBlockCipher(engine);
        }

        // Mixed engine types
        public static IBlockCipher DesEdeCbc() => new CbcBlockCipher(new DesEdeEngine());
        public static IBlockCipher CamelliaCbc() => new CbcBlockCipher(new CamelliaEngine());

        // ChaCha20-Poly1305 standalone AEAD
        public static IAeadCipher ChaCha20Poly1305() => new ChaCha20Poly1305();

        // String-based cipher factory
        public static IBufferedCipher ViaStringCbc()  => CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
        public static IBufferedCipher ViaStringGcm()  => CipherUtilities.GetCipher("AES/GCM/NoPadding");
        public static IBufferedCipher ViaStringRsa()  => CipherUtilities.GetCipher("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }

    // =========================================================================
    // Stream Ciphers
    // Covers: ChaCha7539Engine, ChaChaEngine, Salsa20Engine, XSalsa20Engine,
    //         HC128Engine, HC256Engine, Snow3GEngine, VmpcEngine, VmpcKsaEngine,
    //         Grain128Engine, Grain128AEADEngine, RC4Engine, ZucEngine.
    // Expected algo tags: chacha20, chacha, salsa20, xsalsa20, hc128, hc256,
    //   snow3g, vmpc, vmpc-ksa, grain128, grain128-aead, rc4, zuc
    // =========================================================================
    public static class BcStreamCipherTests
    {
        public static IStreamCipher ChaCha20()      => new ChaCha7539Engine();
        public static IStreamCipher ChaCha()        => new ChaChaEngine();
        public static IStreamCipher Salsa20()       => new Salsa20Engine();
        public static IStreamCipher XSalsa20()      => new XSalsa20Engine();
        public static IStreamCipher HC128()         => new HC128Engine();
        public static IStreamCipher HC256()         => new HC256Engine();
        public static IStreamCipher Snow3G()        => new Snow3GEngine();
        public static IStreamCipher Vmpc()          => new VmpcEngine();
        public static IStreamCipher VmpcKsa()       => new VmpcKsaEngine();
        public static IStreamCipher Grain128()      => new Grain128Engine();
        public static IAeadCipher   Grain128Aead()  => new Grain128AEADEngine();
        public static IStreamCipher RC4()           => new RC4Engine();
        public static IStreamCipher Zuc()           => new ZucEngine();
        public static IStreamCipher Isaac()         => new IsaacEngine();
    }

    // =========================================================================
    // RSA
    // Covers: RsaEngine, RsaBlindedEngine, RsaKeyPairGenerator, OaepEncoding
    //         (SHA-256 and variable-based), Pkcs1Encoding, Iso9796d1Encoding,
    //         PssSigner, Iso9796d2Signer, X931Signer.
    // Expected algo tags: rsa, rsa-keygen, rsa-oaep-sha256, rsa-oaep-sha512,
    //   rsa-pkcs1, rsa-iso9796d1, rsa-pss-sha256, rsa-iso9796d2-sha256,
    //   rsa-x931-sha256
    // =========================================================================
    public static class BcRsaTests
    {
        // Raw engine instantiation
        public static IAsymmetricBlockCipher RsaEngine()        => new RsaEngine();
        public static IAsymmetricBlockCipher RsaBlindedEngine() => new RsaBlindedEngine();

        // Key pair generation
        public static IAsymmetricCipherKeyPairGenerator RsaKeyGen() => new RsaKeyPairGenerator();

        // OaepEncoding — direct digest argument
        public static IAsymmetricBlockCipher OaepSha256Direct() =>
            new OaepEncoding(new RsaBlindedEngine(), new Sha256Digest());
        public static IAsymmetricBlockCipher OaepSha512Direct() =>
            new OaepEncoding(new RsaBlindedEngine(), new Sha512Digest());
        public static IAsymmetricBlockCipher OaepSha1Direct() =>
            new OaepEncoding(new RsaBlindedEngine(), new Sha1Digest());

        // OaepEncoding — variable-based digest argument (data-flow path)
        public static IAsymmetricBlockCipher OaepSha384Variable()
        {
            var digest = new Sha384Digest();
            return new OaepEncoding(new RsaBlindedEngine(), digest);
        }

        // Pkcs1Encoding
        public static IAsymmetricBlockCipher Pkcs1Enc() => new Pkcs1Encoding(new RsaBlindedEngine());

        // Iso9796d1Encoding
        public static IAsymmetricBlockCipher Iso9796d1() => new Iso9796d1Encoding(new RsaBlindedEngine());

        // PssSigner — direct digest argument
        public static ISigner PssSha256Direct() => new PssSigner(new RsaBlindedEngine(), new Sha256Digest());
        public static ISigner PssSha512Direct() => new PssSigner(new RsaBlindedEngine(), new Sha512Digest());

        // PssSigner — variable-based digest (data-flow path)
        public static ISigner PssSha384Variable()
        {
            var digest = new Sha384Digest();
            return new PssSigner(new RsaBlindedEngine(), digest);
        }

        // Iso9796d2Signer
        public static ISigner Iso9796d2Sha256() =>
            new Iso9796d2Signer(new RsaEngine(), new Sha256Digest());

        // X931Signer
        public static ISigner X931Sha256() =>
            new X931Signer(new RsaEngine(), new Sha256Digest());
    }

    // =========================================================================
    // EC, Ed, X-curves, SM2, GOST EC, and utility factories
    // Covers: ECDsaSigner, ECNRSigner, ECKeyPairGenerator, ECDHBasicAgreement,
    //         ECDHCBasicAgreement, ECMqvBasicAgreement, ECGOST3410Signer,
    //         SM2Signer, SM2Engine, SM2Agreement, Ed25519Signer,
    //         Ed25519ctxSigner, Ed25519phSigner, Ed448Signer, Ed448phSigner,
    //         X25519Agreement, X448Agreement, Ed25519/448/X25519/X448 key-pair
    //         generators, SignerUtilities, KeyPairGeneratorUtilities,
    //         AgreementUtilities factories.
    // =========================================================================
    public static class BcEcTests
    {
        // ECDSA
        public static ISigner EcdsaSigner()  => new ECDsaSigner();
        public static ISigner EcnrSigner()   => new ECNRSigner();

        // EC key pair generation
        public static IAsymmetricCipherKeyPairGenerator EcKeyGen() => new ECKeyPairGenerator();

        // EC key agreement
        public static IBasicAgreement EcdhBasic()  => new ECDHBasicAgreement();
        public static IBasicAgreement EcdhC()      => new ECDHCBasicAgreement();
        public static IBasicAgreement EcMqv()      => new ECMqvBasicAgreement();

        // GOST EC
        public static ISigner EcGost3410() => new ECGOST3410Signer();

        // SM2
        public static ISigner  Sm2Signer()    => new SM2Signer();
        public static IAsymmetricBlockCipher Sm2Encrypt() => new SM2Engine();
        public static IBasicAgreement Sm2Dh() => new SM2Agreement();

        // Ed25519 / Ed448
        public static ISigner Ed25519()    => new Ed25519Signer();
        public static ISigner Ed25519Ctx() => new Ed25519ctxSigner();
        public static ISigner Ed25519Ph()  => new Ed25519phSigner();
        public static ISigner Ed448()      => new Ed448Signer();
        public static ISigner Ed448Ph()    => new Ed448phSigner();

        // X25519 / X448 agreement
        public static IRawAgreement X25519() => new X25519Agreement();
        public static IRawAgreement X448()   => new X448Agreement();

        // Dedicated key-pair generators for Ed/X curves
        public static IAsymmetricCipherKeyPairGenerator Ed25519KeyGen() => new Ed25519KeyPairGenerator();
        public static IAsymmetricCipherKeyPairGenerator Ed448KeyGen()   => new Ed448KeyPairGenerator();
        public static IAsymmetricCipherKeyPairGenerator X25519KeyGen()  => new X25519KeyPairGenerator();
        public static IAsymmetricCipherKeyPairGenerator X448KeyGen()    => new X448KeyPairGenerator();

        // String-based utility factories
        public static ISigner   ViaStringSha256WithRsa()   => SignerUtilities.GetSigner("SHA256withRSA");
        public static ISigner   ViaStringSha256WithEcdsa() => SignerUtilities.GetSigner("SHA256withECDSA");
        public static IAsymmetricCipherKeyPairGenerator ViaStringRsaKeyGen() =>
            KeyPairGeneratorUtilities.GetKeyPairGenerator("RSA");
        public static IAsymmetricCipherKeyPairGenerator ViaStringEcKeyGen() =>
            KeyPairGeneratorUtilities.GetKeyPairGenerator("EC");
        public static IBasicAgreement ViaStringEcdh()  => AgreementUtilities.GetBasicAgreement("ECDH");
        public static IBasicAgreement ViaStringEcdhC() => AgreementUtilities.GetBasicAgreement("ECDHC");
    }

    // =========================================================================
    // DSA and ElGamal
    // Covers: DsaSigner, DsaKeyPairGenerator, GOST3410Signer,
    //         ElGamalEngine, ElGamalKeyPairGenerator.
    // Expected algo tags: dsa, dsa-keygen, gost3410, elgamal, elgamal-keygen
    // =========================================================================
    public static class BcDsaTests
    {
        public static ISigner  DsaSigner()     => new DsaSigner();
        public static IAsymmetricCipherKeyPairGenerator DsaKeyGen() => new DsaKeyPairGenerator();
        public static ISigner  Gost3410()      => new GOST3410Signer();
        public static IAsymmetricBlockCipher ElGamal() => new ElGamalEngine();
        public static IAsymmetricCipherKeyPairGenerator ElGamalKeyGen() => new ElGamalKeyPairGenerator();
    }

    // =========================================================================
    // Key Derivation Functions
    // Covers: Pkcs5S1ParametersGenerator (PBKDF1), Pkcs5S2ParametersGenerator
    //         (PBKDF2), HkdfBytesGenerator (HKDF), MGF1BytesGenerator,
    //         ConcatenationKdfGenerator, KdfCounterBytesGenerator,
    //         SCrypt.Generate, Argon2BytesGenerator, BCrypt.Generate.
    // Expected algo tags: pbkdf1, pbkdf2-sha256, hkdf-sha256, mgf1-sha256,
    //   concat-kdf-sha256, kdf-counter, scrypt, argon2, bcrypt
    // =========================================================================
    public static class BcKdfTests
    {
        // PBKDF1
        public static PbeParametersGenerator Pbkdf1() =>
            new Pkcs5S1ParametersGenerator(new MD5Digest());

        // PBKDF2 — direct digest argument
        public static PbeParametersGenerator Pbkdf2Sha256Direct() =>
            new Pkcs5S2ParametersGenerator(new Sha256Digest());
        public static PbeParametersGenerator Pbkdf2Sha512Direct() =>
            new Pkcs5S2ParametersGenerator(new Sha512Digest());

        // PBKDF2 — variable-based digest (data-flow path)
        public static PbeParametersGenerator Pbkdf2Sha384Variable()
        {
            var digest = new Sha384Digest();
            return new Pkcs5S2ParametersGenerator(digest);
        }

        // HKDF — direct and variable
        public static IDerivationFunction HkdfSha256Direct() =>
            new HkdfBytesGenerator(new Sha256Digest());
        public static IDerivationFunction HkdfSha512Variable()
        {
            var digest = new Sha512Digest();
            return new HkdfBytesGenerator(digest);
        }

        // MGF1
        public static IDerivationFunction Mgf1Sha256() => new MGF1BytesGenerator(new Sha256Digest());

        // Concatenation KDF
        public static IDerivationFunction ConcatKdfSha256() =>
            new ConcatenationKdfGenerator(new Sha256Digest());

        // KDF counter
        public static void KdfCounter()
        {
            _ = new KdfCounterBytesGenerator(new CMac(new AesEngine()));
        }

        // SCrypt — static method
        public static byte[] ScryptGenerate() =>
            SCrypt.Generate(new byte[32], new byte[32], 16384, 8, 1, 32);

        // Argon2
        public static void Argon2()
        {
            _ = new Argon2BytesGenerator();
        }

        // BCrypt — static method
        public static byte[] BCryptGenerate() =>
            BCrypt.Generate(new byte[32], new byte[16], 10);
    }

    // =========================================================================
    // CSPRNG
    // Covers: SecureRandom constructor, SecureRandom.GetInstance factory,
    //         DigestRandomGenerator, VmpcRandomGenerator, SP800SecureRandomBuilder.
    // Expected algo tags: csprng, digest-prng-sha256, vmpc-prng, sp800-prng
    // =========================================================================
    public static class BcRandomTests
    {
        // SecureRandom constructor
        public static SecureRandom SecureRandomDefault() => new SecureRandom();

        // SecureRandom factory
        public static SecureRandom SecureRandomInstance() =>
            SecureRandom.GetInstance("SHA256PRNG");

        // DigestRandomGenerator — direct digest
        public static void DigestPrngSha256Direct()
        {
            _ = new DigestRandomGenerator(new Sha256Digest());
        }

        // DigestRandomGenerator — variable-based digest (data-flow path)
        public static void DigestPrngSha512Variable()
        {
            var digest = new Sha512Digest();
            _ = new DigestRandomGenerator(digest);
        }

        // VmpcRandomGenerator
        public static void VmpcPrng()
        {
            _ = new VmpcRandomGenerator();
        }

        // SP800SecureRandomBuilder
        public static void Sp800Prng()
        {
            _ = new SP800SecureRandomBuilder();
        }
    }

    // =========================================================================
    // X.509 / PKI / PEM / PKCS
    // Covers: X509V1CertificateGenerator, X509V3CertificateGenerator,
    //         X509V2CrlGenerator, X509CertificateParser, PkixCertPathBuilder,
    //         PkixCertPathValidator, Pkcs12Store, PemReader, PemWriter,
    //         Pkcs10CertificationRequest, Pkcs8Generator.
    // Expected algo tags: x509v1-cert-gen, x509v3-cert-gen, x509v2-crl-gen,
    //   x509-parse, pkix-certpath-build, pkix-certpath-validate,
    //   pkcs12, pem-read, pem-write, pkcs10-csr, pkcs8-export
    // =========================================================================
    public static class BcPkiTests
    {
        public static void X509V1Gen()
        {
            _ = new X509V1CertificateGenerator();
        }

        public static void X509V3Gen()
        {
            _ = new X509V3CertificateGenerator();
        }

        public static void X509CrlGen()
        {
            _ = new X509V2CrlGenerator();
        }

        public static void X509Parser()
        {
            _ = new X509CertificateParser();
        }

        public static void PkixPathBuilder()
        {
            _ = new PkixCertPathBuilder();
        }

        public static void PkixPathValidator()
        {
            _ = new PkixCertPathValidator();
        }

        public static void Pkcs12()
        {
            _ = new Pkcs12Store();
        }

        public static void PemRead(TextReader reader)
        {
            _ = new PemReader(reader);
        }

        public static void PemWrite(TextWriter writer)
        {
            _ = new PemWriter(writer);
        }

        public static void Pkcs10Csr()
        {
            // Pkcs10CertificationRequest is constructed from encoded bytes in practice
            _ = typeof(Pkcs10CertificationRequest);  // reference to ensure detection
        }

        public static void Pkcs8Export()
        {
            _ = new Pkcs8Generator(null, null);
        }
    }

    // =========================================================================
    // Block cipher padding and buffered cipher wrappers
    // Expected algo tags: padding-pkcs7, padding-zerobyte, padding-x923,
    //                     padding-iso10126, padding-iso7816d4, padding-tbc,
    //                     aes-buffered, 3des-buffered
    // =========================================================================
    public static class BcPaddingTests
    {
        public static IBufferedCipher AesPkcs7()   => new PaddedBufferedBlockCipher(new AesEngine(), new Pkcs7Padding());
        public static IBufferedCipher AesX923()    => new PaddedBufferedBlockCipher(new AesEngine(), new X923Padding());
        public static IBufferedCipher AesIso10126() => new PaddedBufferedBlockCipher(new AesEngine(), new ISO10126d2Padding());
        public static IBufferedCipher AesIso7816() => new PaddedBufferedBlockCipher(new AesEngine(), new ISO7816d4Padding());
        public static IBufferedCipher AesZeroByte() => new PaddedBufferedBlockCipher(new AesEngine(), new ZeroBytePadding());
        public static IBufferedCipher AesTbc()     => new PaddedBufferedBlockCipher(new AesEngine(), new TbcPadding());
        public static IBufferedCipher TripleDesUnpadded() => new BufferedBlockCipher(new DesEdeEngine());
    }

    // =========================================================================
    // Key wrapping
    // Expected algo tags: aes-kw, aes-kwp, 3des-kw, camellia-kw, aria-kw,
    //                     rc2-kw, keywrap:aeswrap
    // =========================================================================
    public static class BcKeyWrapTests
    {
        public static object AesKw()        => new AesWrapEngine();
        public static object AesKwp()       => new AesWrapPadEngine();
        public static object TripleDesKw()  => new DesEdeWrapEngine();
        public static object CamelliaKw()   => new CamelliaWrapEngine();
        public static object AriaKw()       => new AriaWrapEngine();
        public static object Rc2Kw()        => new Rc2WrapEngine();
        public static object Rfc3394Aes()   => new Rfc3394WrapEngine(new AesEngine());
        public static object Rfc5649Aes()   => new Rfc5649WrapEngine(new AesEngine());
        public static object ViaFactory()   => WrapperUtilities.GetWrapper("AESWRAP");
    }

    // =========================================================================
    // Lightweight / NIST LWC AEAD ciphers and additional AEAD modes
    // Expected algo tags: ascon, elephant, isap, photon-beetle, schwaemm,
    //                     xoodyak, romulus, tinyjambu, aes-gcm-siv, aes-xts
    // =========================================================================
    public static class BcLightweightAeadTests
    {
        public static IAeadCipher Ascon()        => new AsconEngine(1);
        public static IAeadCipher Elephant()     => new ElephantEngine(1);
        public static IAeadCipher Isap()         => new IsapEngine(1);
        public static IAeadCipher PhotonBeetle() => new PhotonBeetleEngine(1);
        public static IAeadCipher Sparkle()      => new SparkleEngine(1);
        public static IAeadCipher Xoodyak()      => new XoodyakEngine();
        public static IAeadCipher Romulus()      => new RomulusEngine(1);
        public static IAeadCipher TinyJambu()    => new TinyJambuEngine(1);

        public static IAeadBlockCipher AesGcmSiv() => new GcmSivBlockCipher(new AesEngine());
        public static IAeadBlockCipher KalynaKGcm() => new KGcmBlockCipher(new DstU7624Engine(128));
        public static IBlockCipher AesXts()        => new XtsBlockCipher(new AesEngine());
        public static IBlockCipher KuznyechikCtr() => new G3413CtrBlockCipher(new Gost28147Engine());
        public static IAeadBlockCipher KalynaKCcm() => new KCcmBlockCipher(new DstU7624Engine(128));
        public static IBlockCipher KalynaKXts()     => new KXtsBlockCipher(new DstU7624Engine(128));
        public static IBlockCipher KuznyechikCbc()  => new G3413CbcBlockCipher(new Gost28147Engine());
    }

    // =========================================================================
    // Post-quantum algorithms
    // Expected algo tags: ml-kem, kyber, ml-dsa, dilithium, slh-dsa,
    //                     sphincs-plus, falcon, ntru, ntru-prime, frodokem,
    //                     saber, bike, hqc, classic-mceliece, picnic, rainbow,
    //                     xmss, xmss-mt, lms, newhope
    // =========================================================================
    public static class BcPostQuantumTests
    {
        private static readonly SecureRandom Random = new SecureRandom();

        public static object MlKem()          => new MLKemGenerator(Random);
        public static object MlKemKeyGen()    => new MLKemKeyPairGenerator();
        public static object Kyber()          => new KyberKemGenerator(Random);
        public static object MlDsa()          => new MLDsaSigner();
        public static object Dilithium()      => new DilithiumSigner();
        public static object SlhDsa()         => new SlhDsaSigner();
        public static object SphincsPlus()    => new SphincsPlusSigner();
        public static object Falcon()         => new FalconSigner();
        public static object Ntru()           => new NtruKemGenerator(Random);
        public static object NtruPrime()      => new SntruPrimeKemGenerator(Random);
        public static object FrodoKem()       => new FrodoKemGenerator(Random);
        public static object Saber()          => new SaberKemGenerator(Random);
        public static object Bike()           => new BikeKemGenerator(Random);
        public static object Hqc()            => new HqcKemGenerator(Random);
        public static object ClassicMcEliece() => new CmceKemGenerator(Random);
        public static object Picnic()         => new PicnicSigner();
        public static object Rainbow()        => new RainbowSigner();
        public static object Xmss()           => new XmssSigner();
        public static object XmssMt()         => new XmssMTSigner();
        public static object Lms()            => new LmsSigner();
        public static object Hss()            => new HssSigner();
        public static object NewHope()        => new NHAgreement();
    }

    // =========================================================================
    // Named elliptic curves and explicit key strengths
    // Expected algo tags: ec-curve:secp256r1, ec-curve:secp384r1,
    //                     ec-curve:brainpoolp256r1, ec-curve:sm2p256v1,
    //                     rsa-4096-keygen, dl-params-2048
    // =========================================================================
    public static class BcCurveAndStrengthTests
    {
        public static object NistP256()      => ECNamedCurveTable.GetByName("secp256r1");
        public static object NistP384Custom() => CustomNamedCurves.GetByName("secp384r1");
        public static object SecCurve()      => SecNamedCurves.GetByName("secp521r1");
        public static object Brainpool()     => TeleTrusTNamedCurves.GetByName("brainpoolP256r1");
        public static object Sm2Curve()      => GMNamedCurves.GetByName("sm2p256v1");
        public static object CurveOid()      => ECNamedCurveTable.GetOid("secp256k1");

        public static RsaKeyGenerationParameters Rsa4096Params() =>
            new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 4096, 100);

        public static void Dsa2048Params()
        {
            var generator = new DsaParametersGenerator();
            generator.Init(2048, 80, new SecureRandom());
        }
    }

    // =========================================================================
    // Integrated encryption schemes and protocol layers
    // Expected algo tags: ies, ecies-eth, sm2-dh, tls, cms-sign, cms-encrypt,
    //                     pgp-encrypt, pgp-sign, pgp-keygen
    // =========================================================================
    public static class BcProtocolTests
    {
        public static object Ies() =>
            new IesEngine(new ECDHBasicAgreement(), new Kdf2BytesGenerator(new Sha256Digest()), new HMac(new Sha256Digest()));

        public static object EthereumIes() =>
            new EthereumIesEngine(new ECDHBasicAgreement(), new Kdf2BytesGenerator(new Sha256Digest()), new HMac(new Sha256Digest()));

        public static object Sm2Exchange()  => new Sm2KeyExchange();
        public static object TlsClient(System.IO.Stream stream) => new TlsClientProtocol(stream);
        public static object CmsSign()      => new CmsSignedDataGenerator();
        public static object CmsEncrypt()   => new CmsEnvelopedDataGenerator();
        public static object PgpEncrypt()   => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256);
        public static object PgpSign()      => new PgpSignatureGenerator(PublicKeyAlgorithmTag.RsaSign, HashAlgorithmTag.Sha256);
        public static object PgpKeyGen()    => new PgpKeyRingGenerator();
    }

    // =========================================================================
    // Additional digests, engines and MACs
    // Expected algo tags: kupyna, haraka-256, blake2bp, ascon-hash, xoodyak,
    //                     rijndael, kalyna, rc5, shacal2, lea, kmac, tuplehash
    // =========================================================================
    public static class BcAdditionalPrimitiveTests
    {
        public static IDigest Kupyna()      => new DSTU7564Digest(256);
        public static IDigest Haraka256()   => new Haraka256Digest();
        public static IDigest Blake2bp()    => new Blake2bpDigest(512);
        public static IDigest AsconHash()   => new AsconDigest();
        public static IDigest XoodyakHash() => new XoodyakDigest();

        public static IBlockCipher Rijndael() => new RijndaelEngine(256);
        public static IBlockCipher Kalyna()   => new DstU7624Engine(128);
        public static IBlockCipher Rc5()      => new Rc532Engine();
        public static IBlockCipher Shacal2()  => new Shacal2Engine();
        public static IBlockCipher Lea()      => new LeaEngine();

        public static IMac Kmac()       => new KMac(256, null);
        public static IMac TupleHash()  => new TupleHash(256, null);
        public static IMac KupynaMac()  => new DSTU7564Mac(256);
        public static IMac SkeinMac()   => new SkeinMac(512, 256);
    }

    // =========================================================================
    // Remaining primitive variants and unresolvable-argument fallbacks
    // Expected algo tags: haraka-512, blake2sp, blake2xs, ascon-xof, esch,
    //                     parallelhash, blake3-mac, kalyna-mac, gost28147-mac,
    //                     shacal, seed-kw, aria-kwp, kalyna-kw, gost28147-kw,
    //                     rfc3394-kw, rfc5649-kwp, buffered-cipher, ecies,
    //                     gemss, sike, dtls, cms-signed, cms-enveloped,
    //                     pgp-keypair, ocsp-request, rfc3161-timestamp, dl-params
    // =========================================================================
    public static class BcRemainingPrimitiveTests
    {
        public static IDigest Haraka512()  => new Haraka512Digest();
        public static IDigest Blake2sp()   => new Blake2spDigest(256);
        public static IDigest Blake2xs()   => new Blake2xsDigest(256);
        public static IDigest AsconXof()   => new AsconXof();
        public static IDigest Esch()       => new SparkleDigest();

        public static IMac ParallelHash()  => new ParallelHash(256, null, 64);
        public static IMac Blake3Mac()     => new Blake3Mac(256);
        public static IMac KalynaMac()     => new DSTU7624Mac(128, 128);
        public static IMac Gost28147Mac()  => new Gost28147Mac();

        public static IBlockCipher Shacal() => new ShacalEngine();

        public static object SeedKw()       => new SeedWrapEngine();
        public static object AriaKwp()      => new AriaWrapPadEngine();
        public static object KalynaKw()     => new DstU7624WrapEngine(128);
        public static object Gost28147Kw()  => new Gost28147WrapEngine();

        public static object Ecies() =>
            new EciesEngine(new ECDHBasicAgreement(), new Kdf1BytesGenerator(new Sha256Digest()), new HMac(new Sha256Digest()));

        public static object GeMSS()        => new GeMSSSigner();
        public static object Sike()         => new SikeKemGenerator(new SecureRandom());
        public static object Dtls()         => new DtlsClientProtocol();
        public static object CmsSigned(byte[] encoded)    => new CmsSignedData(encoded);
        public static object CmsEnveloped(byte[] encoded) => new CmsEnvelopedData(encoded);
        public static object PgpKeyPair()   => new PgpKeyPair();
        public static object OcspRequest()  => new OcspReqGenerator();
        public static object Timestamp()    => new TimeStampRequestGenerator();
    }

    // =========================================================================
    // Fallback paths where the wrapped cipher or key size is not statically known
    // Expected algo tags: buffered-cipher, rfc3394-kw, rfc5649-kwp, dl-params
    // =========================================================================
    public static class BcUnresolvableArgumentTests
    {
        public static IBufferedCipher Buffered(IBlockCipher cipher) => new BufferedBlockCipher(cipher);
        public static object Rfc3394(IBlockCipher cipher)  => new Rfc3394WrapEngine(cipher);
        public static object Rfc5649(IBlockCipher cipher)  => new Rfc5649WrapEngine(cipher);

        public static void DhParamsFromVariable(int size)
        {
            var generator = new DHParametersGenerator();
            generator.Init(size, 80, new SecureRandom());
        }
    }

    // =========================================================================
    // Fallback paths where the wrapped digest or cipher is not statically known
    // Expected algo tags: hmac, cmac, poly1305, cbc-mac, cfb-mac, gcm-mode,
    //                     ccm-mode, eax-mode, ocb-mode, cbc-mode, cfb-mode,
    //                     ofb-mode, ctr-mode, gofb-mode, cts-mode, pbkdf2,
    //                     hkdf, mgf1, concat-kdf, digest-prng, rsa-oaep,
    //                     rsa-pss, rsa-iso9796d2, rsa-x931, sha3, keccak,
    //                     shake, cshake, skein
    // =========================================================================
    public static class BcUnresolvedDigestAndCipherTests
    {
        public static IMac Hmac(IDigest digest)          => new HMac(digest);
        public static IMac Cmac(IBlockCipher cipher)     => new CMac(cipher);
        public static IMac Poly1305(IBlockCipher cipher) => new Poly1305(cipher);
        public static IMac CbcMac(IBlockCipher cipher)   => new CBCBlockCipherMac(cipher);
        public static IMac CfbMac(IBlockCipher cipher)   => new CFBBlockCipherMac(cipher);

        public static IAeadBlockCipher Gcm(IBlockCipher c) => new GcmBlockCipher(c);
        public static IAeadBlockCipher Ccm(IBlockCipher c) => new CcmBlockCipher(c);
        public static IAeadBlockCipher Eax(IBlockCipher c) => new EaxBlockCipher(c);
        public static IAeadBlockCipher Ocb(IBlockCipher c) => new OcbBlockCipher(c, c);

        public static IBlockCipher Cbc(IBlockCipher c)  => new CbcBlockCipher(c);
        public static IBlockCipher Cfb(IBlockCipher c)  => new CfbBlockCipher(c, 128);
        public static IBlockCipher Ofb(IBlockCipher c)  => new OfbBlockCipher(c, 128);
        public static IBlockCipher Ctr(IBlockCipher c)  => new SicBlockCipher(c);
        public static IBlockCipher Gofb(IBlockCipher c) => new GofbBlockCipher(c);
        public static IBlockCipher Cts(IBlockCipher c)  => new CtsBlockCipher(c);

        public static PbeParametersGenerator Pbkdf2(IDigest d) => new Pkcs5S2ParametersGenerator(d);
        public static IDerivationFunction Hkdf(IDigest d)      => new HkdfBytesGenerator(d);
        public static IDerivationFunction Mgf1(IDigest d)      => new MGF1BytesGenerator(d);
        public static IDerivationFunction ConcatKdf(IDigest d) => new ConcatenationKdfGenerator(d);
        public static object DigestPrng(IDigest d)             => new DigestRandomGenerator(d);

        public static IAsymmetricBlockCipher RsaOaep(IDigest d) => new OaepEncoding(new RsaEngine(), d);
        public static ISigner RsaPss(IDigest d)        => new PssSigner(new RsaEngine(), d);
        public static ISigner RsaIso9796d2(IDigest d)  => new Iso9796d2Signer(new RsaEngine(), d);
        public static ISigner RsaX931(IDigest d)       => new X931Signer(new RsaEngine(), d);

        public static IDigest Sha3(int bits)   => new Sha3Digest(bits);
        public static IDigest Keccak(int bits) => new KeccakDigest(bits);
        public static IDigest Shake(int bits)  => new ShakeDigest(bits);
        public static IDigest CShake(int bits) => new CShakeDigest(bits);
        public static IDigest Skein(int state, int output) => new SkeinDigest(state, output);
    }

    // =========================================================================
    // Remaining fixed-name primitives
    // Expected algo tags: siphash-128, pkcs10-csr
    // =========================================================================
    public static class BcRemainingFixedNameTests
    {
        public static IMac SipHash128() => new SipHash128();
        public static Pkcs10CertificationRequest Csr(byte[] encoded) =>
            new Pkcs10CertificationRequest(encoded);
    }

    // =========================================================================
    // Format-preserving encryption (NIST SP 800-38G): FF1 / FF3-1
    // Expected algo tags: aes-ff1, aes-ff3-1, ff1-mode, ff3-1-mode
    // =========================================================================
    public static class BcFpeTests
    {
        public static IBlockCipher Ff1Aes()   => new FpeFf1Engine(new AesEngine(), 10);
        public static IBlockCipher Ff31Aes()  => new FpeFf3_1Engine(new AesEngine(), 10);

        public static IBlockCipher Ff1Unresolved(IBlockCipher cipher)  => new FpeFf1Engine(cipher, 10);
        public static IBlockCipher Ff31Unresolved(IBlockCipher cipher) => new FpeFf3_1Engine(cipher, 10);
    }

}
