/**
 * @name Crypto inventory — BouncyCastle C# (Org.BouncyCastle)
 * @description Inventory of BouncyCastle cryptographic API usage including hash
 *              digests, MACs, symmetric cipher engines and block-cipher modes,
 *              stream ciphers, RSA, ECDSA, ECDH, DSA, Ed/X-curves, SM2, GOST,
 *              key derivation, CSPRNG, and X.509/PKI.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/csharp-cbom-bouncycastle
 * @tags security
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow

// Note: namespace guards are intentionally omitted — in --build-mode=none,
// NuGet types are unresolved so getNamespace().getFullName() returns "".
// Detection relies on class names alone, which are sufficiently distinctive.

// =============================================================================
// Private mapping helpers
// =============================================================================

/** Maps fixed-name BouncyCastle digest class names to canonical algo labels. */
private predicate bcDigestClassName(string cls, string algo) {
  cls = "Sha1Digest"               and algo = "sha1"         or
  cls = "Sha224Digest"             and algo = "sha224"       or
  cls = "Sha256Digest"             and algo = "sha256"       or
  cls = "Sha384Digest"             and algo = "sha384"       or
  cls = "Sha512Digest"             and algo = "sha512"       or
  cls = "MD2Digest"                and algo = "md2"          or
  cls = "MD4Digest"                and algo = "md4"          or
  cls = "MD5Digest"                and algo = "md5"          or
  cls = "RipeMD128Digest"          and algo = "ripemd128"    or
  cls = "RipeMD160Digest"          and algo = "ripemd160"    or
  cls = "RipeMD256Digest"          and algo = "ripemd256"    or
  cls = "RipeMD320Digest"          and algo = "ripemd320"    or
  cls = "WhirlpoolDigest"          and algo = "whirlpool"    or
  cls = "TigerDigest"              and algo = "tiger"        or
  cls = "SM3Digest"                and algo = "sm3"          or
  cls = "GOST3411Digest"           and algo = "gost3411"     or
  cls = "GOST3411_2012_256Digest"  and algo = "streebog-256" or
  cls = "GOST3411_2012_512Digest"  and algo = "streebog-512" or
  cls = "Blake2bDigest"            and algo = "blake2b"      or
  cls = "Blake2sDigest"            and algo = "blake2s"      or
  cls = "Blake2bpDigest"           and algo = "blake2bp"     or
  cls = "Blake2spDigest"           and algo = "blake2sp"     or
  cls = "Blake2xsDigest"           and algo = "blake2xs"     or
  cls = "Blake3Digest"             and algo = "blake3"       or
  cls = "DSTU7564Digest"           and algo = "kupyna"       or
  cls = "Haraka256Digest"          and algo = "haraka-256"   or
  cls = "Haraka512Digest"          and algo = "haraka-512"   or
  cls = "AsconDigest"              and algo = "ascon-hash"   or
  cls = "AsconXof"                 and algo = "ascon-xof"    or
  cls = "PhotonBeetleDigest"       and algo = "photon-beetle" or
  cls = "SparkleDigest"            and algo = "esch"         or
  cls = "XoodyakDigest"            and algo = "xoodyak"      or
  cls = "IsapDigest"               and algo = "isap"         or
  cls = "NullDigest"               and algo = "null-digest"
}

/** Maps BouncyCastle block cipher engine class names to canonical algo labels. */
private predicate bcCipherEngineName(string cls, string algo) {
  cls = "AesEngine"            and algo = "aes"          or
  cls = "AesLightEngine"       and algo = "aes"          or
  cls = "DesEngine"            and algo = "des"          or
  cls = "DesEdeEngine"         and algo = "3des"         or
  cls = "BlowfishEngine"       and algo = "blowfish"     or
  cls = "TwofishEngine"        and algo = "twofish"      or
  cls = "CamelliaEngine"       and algo = "camellia"     or
  cls = "CamelliaLightEngine"  and algo = "camellia"     or
  cls = "Rc2Engine"            and algo = "rc2"          or
  cls = "Rc6Engine"            and algo = "rc6"          or
  cls = "Cast5Engine"          and algo = "cast5"        or
  cls = "Cast6Engine"          and algo = "cast6"        or
  cls = "SerpentEngine"        and algo = "serpent"      or
  cls = "SerpentLightEngine"   and algo = "serpent"      or
  cls = "SkipjackEngine"       and algo = "skipjack"     or
  cls = "TeaEngine"            and algo = "tea"          or
  cls = "XteaEngine"           and algo = "xtea"         or
  cls = "SM4Engine"            and algo = "sm4"          or
  cls = "AriaEngine"           and algo = "aria"         or
  cls = "Gost28147Engine"      and algo = "gost28147"    or
  cls = "IdeaEngine"           and algo = "idea"         or
  cls = "SeedEngine"           and algo = "seed"         or
  cls = "NoekeonEngine"        and algo = "noekeon"      or
  cls = "ThreefishEngine"      and algo = "threefish"    or
  cls = "RijndaelEngine"       and algo = "rijndael"     or
  cls = "DstU7624Engine"       and algo = "kalyna"       or
  cls = "Rc532Engine"          and algo = "rc5"          or
  cls = "Rc564Engine"          and algo = "rc5"          or
  cls = "ShacalEngine"         and algo = "shacal"       or
  cls = "Shacal2Engine"        and algo = "shacal2"      or
  cls = "LeaEngine"            and algo = "lea"          or
  cls = "NullEngine"           and algo = "null-cipher"
}

// =============================================================================
// Argument-resolution helpers (direct + data-flow)
// =============================================================================

/** Holds if `arg` directly instantiates a known BouncyCastle digest. */
private predicate bcDigestArgDirect(Expr arg, string algo) {
  exists(string cls |
    arg.(ObjectCreation).getType().getName() = cls and
    bcDigestClassName(cls, algo)
  )
  or
  // Sha3Digest(bits), KeccakDigest(bits), ShakeDigest(bits)
  exists(string cls, string bits |
    arg.(ObjectCreation).getType().getName() = cls and
    bits = arg.(ObjectCreation).getArgument(0).(Literal).getValue()
  |
    cls = "Sha3Digest"   and algo = "sha3-" + bits   or
    cls = "KeccakDigest" and algo = "keccak-" + bits or
    cls = "ShakeDigest"  and algo = "shake-" + bits
  )
}

/** Holds if `arg` is or flows from a BouncyCastle digest with canonical name `algo`. */
predicate bcDigestArg(Expr arg, string algo) {
  bcDigestArgDirect(arg, algo)
  or
  exists(Expr src |
    src != arg and
    bcDigestArgDirect(src, algo) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

/** Holds if `arg` directly instantiates a known BouncyCastle block cipher engine. */
private predicate bcCipherEngineArgDirect(Expr arg, string algo) {
  exists(string cls |
    arg.(ObjectCreation).getType().getName() = cls and
    bcCipherEngineName(cls, algo)
  )
}

/** Holds if `arg` is or flows from a BouncyCastle block cipher engine with canonical name `algo`. */
predicate bcCipherEngineArg(Expr arg, string algo) {
  bcCipherEngineArgDirect(arg, algo)
  or
  exists(Expr src |
    src != arg and
    bcCipherEngineArgDirect(src, algo) and
    DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(arg))
  )
}

// =============================================================================
// Detection predicates
// =============================================================================

// ---------------------------------------------------------------------------
// Hash Digests
// ---------------------------------------------------------------------------
predicate isBcHashDetection(Expr call, string algo) {
  // Fixed-name digest constructors
  exists(ObjectCreation oc |
    oc = call and
    bcDigestClassName(oc.getType().getName(), algo)
  )
  or
  // Sha3Digest(bits), KeccakDigest(bits), ShakeDigest(bits), CShakeDigest(bits)
  exists(ObjectCreation oc, string cls, string bits |
    oc = call and
    oc.getType().getName() = cls and
    bits = oc.getArgument(0).(Literal).getValue()
  |
    cls = "Sha3Digest"   and algo = "sha3-" + bits   or
    cls = "KeccakDigest" and algo = "keccak-" + bits or
    cls = "ShakeDigest"  and algo = "shake-" + bits  or
    cls = "CShakeDigest" and algo = "cshake-" + bits
  )
  or
  // Sha512tDigest(bitLength) — FIPS 180-4 SHA-512/t (e.g. SHA-512/224, SHA-512/256)
  exists(ObjectCreation oc, string bits |
    oc = call and
    oc.getType().getName() = "Sha512tDigest" and
    bits = oc.getArgument(0).(Literal).getValue() and
    algo = "sha512t-" + bits
  )
  or
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "Sha512tDigest" and
    not exists(oc.getArgument(0).(Literal)) and
    algo = "sha512t"
  )
  or
  // Fallback for parameterised digests with non-literal bit-size argument
  exists(ObjectCreation oc, string cls |
    oc = call and
    oc.getType().getName() = cls and
    (cls = "Sha3Digest" or cls = "KeccakDigest" or cls = "ShakeDigest" or cls = "CShakeDigest") and
    not exists(oc.getArgument(0).(Literal))
  |
    cls = "Sha3Digest"   and algo = "sha3"   or
    cls = "KeccakDigest" and algo = "keccak" or
    cls = "ShakeDigest"  and algo = "shake"  or
    cls = "CShakeDigest" and algo = "cshake"
  )
  or
  // SkeinDigest(stateSizeBits, outputSizeBits) — both literal
  exists(ObjectCreation oc, string s, string o |
    oc = call and
    oc.getType().getName() = "SkeinDigest" and
    s = oc.getArgument(0).(Literal).getValue() and
    o = oc.getArgument(1).(Literal).getValue() and
    algo = "skein-" + s + "-" + o
  )
  or
  // SkeinDigest fallback when sizes are not literals
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "SkeinDigest" and
    not (exists(oc.getArgument(0).(Literal)) and exists(oc.getArgument(1).(Literal))) and
    algo = "skein"
  )
  or
  // DigestUtilities.GetDigest(string) — string-based factory
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "GetDigest" and
    mc.getTarget().getDeclaringType().getName() = "DigestUtilities" and
    algo = "digest:" + mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// MACs
// ---------------------------------------------------------------------------
predicate isBcMacDetection(Expr call, string algo) {
  // HMac(IDigest) — resolve the underlying digest for specific labelling
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "HMac"
  |
    exists(string digestAlgo |
      bcDigestArg(oc.getArgument(0), digestAlgo) and algo = "hmac-" + digestAlgo
    )
    or
    not exists(string d | bcDigestArg(oc.getArgument(0), d)) and algo = "hmac"
  )
  or
  // CMac(IBlockCipher) — resolve the underlying cipher
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "CMac"
  |
    exists(string cipherAlgo |
      bcCipherEngineArg(oc.getArgument(0), cipherAlgo) and algo = cipherAlgo + "-cmac"
    )
    or
    not exists(string c | bcCipherEngineArg(oc.getArgument(0), c)) and algo = "cmac"
  )
  or
  // Poly1305(IBlockCipher) — resolve the underlying cipher
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "Poly1305"
  |
    exists(string cipherAlgo |
      bcCipherEngineArg(oc.getArgument(0), cipherAlgo) and algo = cipherAlgo + "-poly1305"
    )
    or
    not exists(string c | bcCipherEngineArg(oc.getArgument(0), c)) and algo = "poly1305"
  )
  or
  // GMac — wraps an AEAD block cipher (typically AES-GCM)
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "GMac" and
    algo = "aes-gmac"
  )
  or
  // CBCBlockCipherMac / CFBBlockCipherMac — resolve cipher
  exists(ObjectCreation oc, string macCls, string macSuffix |
    oc = call and
    oc.getType().getName() = macCls and
    (
      macCls = "CBCBlockCipherMac" and macSuffix = "-cbc-mac" or
      macCls = "CFBBlockCipherMac" and macSuffix = "-cfb-mac"
    )
  |
    exists(string cipherAlgo |
      bcCipherEngineArg(oc.getArgument(0), cipherAlgo) and algo = cipherAlgo + macSuffix
    )
    or
    not exists(string c | bcCipherEngineArg(oc.getArgument(0), c)) and
    (
      macCls = "CBCBlockCipherMac" and algo = "cbc-mac" or
      macCls = "CFBBlockCipherMac" and algo = "cfb-mac"
    )
  )
  or
  // Standalone MACs with fixed algo labels
  exists(ObjectCreation oc |
    oc = call
  |
    oc.getType().getName() = "ISO9797Alg3Mac" and algo = "iso9797-alg3-mac" or
    oc.getType().getName() = "SipHash"         and algo = "siphash"          or
    oc.getType().getName() = "SipHash128"      and algo = "siphash-128"      or
    oc.getType().getName() = "KMac"            and algo = "kmac"             or
    oc.getType().getName() = "TupleHash"       and algo = "tuplehash"        or
    oc.getType().getName() = "ParallelHash"    and algo = "parallelhash"     or
    oc.getType().getName() = "DSTU7564Mac"     and algo = "kupyna-mac"       or
    oc.getType().getName() = "DSTU7624Mac"     and algo = "kalyna-mac"       or
    oc.getType().getName() = "Gost28147Mac"    and algo = "gost28147-mac"    or
    oc.getType().getName() = "SkeinMac"        and algo = "skein-mac"        or
    oc.getType().getName() = "Blake3Mac"       and algo = "blake3-mac"
  )
  or
  // MacUtilities.GetMac(string) — string-based factory
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "GetMac" and
    mc.getTarget().getDeclaringType().getName() = "MacUtilities" and
    algo = "mac:" + mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// Symmetric ciphers — block cipher engines
// ---------------------------------------------------------------------------
predicate isBcSymmetricEngineDetection(Expr call, string algo) {
  // Block cipher engine constructors
  exists(ObjectCreation oc |
    oc = call and
    bcCipherEngineName(oc.getType().getName(), algo)
  )
  or
  // GeneratorUtilities.GetKeyGenerator(string) — symmetric key-generation factory
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "GetKeyGenerator" and
    mc.getTarget().getDeclaringType().getName() = "GeneratorUtilities" and
    algo = "keygen:" + mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// Symmetric ciphers — block cipher modes and AEAD wrappers
// ---------------------------------------------------------------------------
predicate isBcModeDetection(Expr call, string algo) {
  // AEAD mode wrappers with cipher inference
  exists(ObjectCreation oc, string modeCls, string modeSuffix |
    oc = call and
    oc.getType().getName() = modeCls and
    (
      modeCls = "GcmBlockCipher" and modeSuffix = "-gcm" or
      modeCls = "CcmBlockCipher" and modeSuffix = "-ccm" or
      modeCls = "EaxBlockCipher" and modeSuffix = "-eax" or
      modeCls = "OcbBlockCipher" and modeSuffix = "-ocb"
    )
  |
    exists(string cipherAlgo |
      bcCipherEngineArg(oc.getArgument(0), cipherAlgo) and algo = cipherAlgo + modeSuffix
    )
    or
    not exists(string c | bcCipherEngineArg(oc.getArgument(0), c)) and
    (
      modeCls = "GcmBlockCipher" and algo = "gcm-mode" or
      modeCls = "CcmBlockCipher" and algo = "ccm-mode" or
      modeCls = "EaxBlockCipher" and algo = "eax-mode" or
      modeCls = "OcbBlockCipher" and algo = "ocb-mode"
    )
  )
  or
  // Classical mode wrappers with cipher inference
  exists(ObjectCreation oc, string modeCls, string modeSuffix |
    oc = call and
    oc.getType().getName() = modeCls and
    (
      modeCls = "CbcBlockCipher"  and modeSuffix = "-cbc"  or
      modeCls = "CfbBlockCipher"  and modeSuffix = "-cfb"  or
      modeCls = "OfbBlockCipher"  and modeSuffix = "-ofb"  or
      modeCls = "SicBlockCipher"  and modeSuffix = "-ctr"  or
      modeCls = "GofbBlockCipher" and modeSuffix = "-gofb" or
      modeCls = "CtsBlockCipher"  and modeSuffix = "-cts"
    )
  |
    exists(string cipherAlgo |
      bcCipherEngineArg(oc.getArgument(0), cipherAlgo) and algo = cipherAlgo + modeSuffix
    )
    or
    not exists(string c | bcCipherEngineArg(oc.getArgument(0), c)) and
    (
      modeCls = "CbcBlockCipher"  and algo = "cbc-mode"  or
      modeCls = "CfbBlockCipher"  and algo = "cfb-mode"  or
      modeCls = "OfbBlockCipher"  and algo = "ofb-mode"  or
      modeCls = "SicBlockCipher"  and algo = "ctr-mode"  or
      modeCls = "GofbBlockCipher" and algo = "gofb-mode" or
      modeCls = "CtsBlockCipher"  and algo = "cts-mode"
    )
  )
  or
  // Format-preserving encryption (NIST SP 800-38G): FF1 / FF3-1 — resolve wrapped cipher
  exists(ObjectCreation oc, string modeCls, string modeSuffix |
    oc = call and
    oc.getType().getName() = modeCls and
    (
      modeCls = "FpeFf1Engine"   and modeSuffix = "-ff1"   or
      modeCls = "FpeFf3_1Engine" and modeSuffix = "-ff3-1"
    )
  |
    exists(string cipherAlgo |
      bcCipherEngineArg(oc.getArgument(0), cipherAlgo) and algo = cipherAlgo + modeSuffix
    )
    or
    not exists(string c | bcCipherEngineArg(oc.getArgument(0), c)) and
    (
      modeCls = "FpeFf1Engine"   and algo = "ff1-mode" or
      modeCls = "FpeFf3_1Engine" and algo = "ff3-1-mode"
    )
  )
  or
  // ChaCha20-Poly1305 standalone AEAD (Org.BouncyCastle.Crypto.Modes)
  // Exclude System.Security.Cryptography.ChaCha20Poly1305 — same class name, different library.
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "ChaCha20Poly1305" and
    not oc.getType().(ValueOrRefType).getNamespace().getFullName() = "System.Security.Cryptography" and
    algo = "chacha20-poly1305"
  )
  or
  // CipherUtilities.GetCipher(string) — string-based factory
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "GetCipher" and
    mc.getTarget().getDeclaringType().getName() = "CipherUtilities" and
    algo = "cipher:" + mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// Stream ciphers
// ---------------------------------------------------------------------------
predicate isBcStreamCipherDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call
  |
    oc.getType().getName() = "ChaCha7539Engine"    and algo = "chacha20"       or
    oc.getType().getName() = "ChaChaEngine"        and algo = "chacha"         or
    oc.getType().getName() = "Salsa20Engine"       and algo = "salsa20"        or
    oc.getType().getName() = "XSalsa20Engine"      and algo = "xsalsa20"       or
    oc.getType().getName() = "HC128Engine"         and algo = "hc128"          or
    oc.getType().getName() = "HC256Engine"         and algo = "hc256"          or
    oc.getType().getName() = "Snow3GEngine"        and algo = "snow3g"         or
    oc.getType().getName() = "VmpcEngine"          and algo = "vmpc"           or
    oc.getType().getName() = "VmpcKsaEngine"       and algo = "vmpc-ksa"       or
    oc.getType().getName() = "Grain128Engine"      and algo = "grain128"       or
    oc.getType().getName() = "Grain128AEADEngine"  and algo = "grain128-aead"  or
    oc.getType().getName() = "RC4Engine"           and algo = "rc4"            or
    oc.getType().getName() = "ZucEngine"           and algo = "zuc"            or
    oc.getType().getName() = "IsaacEngine"         and algo = "isaac"
  )
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------
predicate isBcRsaDetection(Expr call, string algo) {
  // Raw RSA engine instantiation
  exists(ObjectCreation oc |
    oc = call and
    (
      oc.getType().getName() = "RsaEngine" or
      oc.getType().getName() = "RsaBlindedEngine"
    ) and
    algo = "rsa"
  )
  or
  // RSA key pair generation
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "RsaKeyPairGenerator" and
    algo = "rsa-keygen"
  )
  or
  // OaepEncoding(engine, hashForOAEP [, mgfHash [, encodingParams]])
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "OaepEncoding"
  |
    exists(string digestAlgo |
      bcDigestArg(oc.getArgument(1), digestAlgo) and algo = "rsa-oaep-" + digestAlgo
    )
    or
    not exists(string d | bcDigestArg(oc.getArgument(1), d)) and algo = "rsa-oaep"
  )
  or
  // Pkcs1Encoding(engine) — PKCS#1 v1.5 encryption
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "Pkcs1Encoding" and
    algo = "rsa-pkcs1"
  )
  or
  // Iso9796d1Encoding
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "Iso9796d1Encoding" and
    algo = "rsa-iso9796d1"
  )
  or
  // PssSigner(engine, digest [, mgfDigest]) — RSA-PSS
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "PssSigner"
  |
    exists(string digestAlgo |
      bcDigestArg(oc.getArgument(1), digestAlgo) and algo = "rsa-pss-" + digestAlgo
    )
    or
    not exists(string d | bcDigestArg(oc.getArgument(1), d)) and algo = "rsa-pss"
  )
  or
  // Iso9796d2Signer(engine, digest)
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "Iso9796d2Signer"
  |
    exists(string digestAlgo |
      bcDigestArg(oc.getArgument(1), digestAlgo) and algo = "rsa-iso9796d2-" + digestAlgo
    )
    or
    not exists(string d | bcDigestArg(oc.getArgument(1), d)) and algo = "rsa-iso9796d2"
  )
  or
  // X931Signer(engine, digest)
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "X931Signer"
  |
    exists(string digestAlgo |
      bcDigestArg(oc.getArgument(1), digestAlgo) and algo = "rsa-x931-" + digestAlgo
    )
    or
    not exists(string d | bcDigestArg(oc.getArgument(1), d)) and algo = "rsa-x931"
  )
}

// ---------------------------------------------------------------------------
// EC, Ed, X-curves, SM2, GOST EC, and asymmetric utility factories
// ---------------------------------------------------------------------------
predicate isBcEcDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call
  |
    oc.getType().getName() = "ECDsaSigner"           and algo = "ecdsa"             or
    oc.getType().getName() = "ECNRSigner"            and algo = "ecnr"              or
    oc.getType().getName() = "ECKeyPairGenerator"    and algo = "ec-keygen"         or
    oc.getType().getName() = "ECDHBasicAgreement"    and algo = "ecdh"              or
    oc.getType().getName() = "ECDHCBasicAgreement"   and algo = "ecdhc"             or
    oc.getType().getName() = "ECMqvBasicAgreement"   and algo = "ecmqv"             or
    oc.getType().getName() = "ECGOST3410Signer"      and algo = "ecgost3410"        or
    oc.getType().getName() = "SM2Signer"             and algo = "sm2-sign"          or
    oc.getType().getName() = "SM2Engine"             and algo = "sm2-encrypt"       or
    oc.getType().getName() = "SM2Agreement"          and algo = "sm2-dh"            or
    oc.getType().getName() = "Ed25519Signer"         and algo = "ed25519"           or
    oc.getType().getName() = "Ed25519ctxSigner"      and algo = "ed25519ctx"        or
    oc.getType().getName() = "Ed25519phSigner"       and algo = "ed25519ph"         or
    oc.getType().getName() = "Ed448Signer"           and algo = "ed448"             or
    oc.getType().getName() = "Ed448phSigner"         and algo = "ed448ph"           or
    oc.getType().getName() = "X25519Agreement"       and algo = "x25519"            or
    oc.getType().getName() = "X448Agreement"         and algo = "x448"              or
    oc.getType().getName() = "Ed25519KeyPairGenerator" and algo = "ed25519-keygen"  or
    oc.getType().getName() = "Ed448KeyPairGenerator"   and algo = "ed448-keygen"    or
    oc.getType().getName() = "X25519KeyPairGenerator"  and algo = "x25519-keygen"   or
    oc.getType().getName() = "X448KeyPairGenerator"    and algo = "x448-keygen"
  )
  or
  // SignerUtilities.GetSigner(string) — string-based signer factory
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "GetSigner" and
    mc.getTarget().getDeclaringType().getName() = "SignerUtilities" and
    algo = "signer:" + mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
  or
  // KeyPairGeneratorUtilities.GetKeyPairGenerator(string) — string-based key-pair-gen factory
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "GetKeyPairGenerator" and
    mc.getTarget().getDeclaringType().getName() = "KeyPairGeneratorUtilities" and
    algo = "keypairgen:" + mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
  or
  // AgreementUtilities.GetBasicAgreement(string) — string-based agreement factory
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "GetBasicAgreement" and
    mc.getTarget().getDeclaringType().getName() = "AgreementUtilities" and
    algo = "agreement:" + mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// DSA and ElGamal
// ---------------------------------------------------------------------------
predicate isBcDsaElGamalDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call
  |
    oc.getType().getName() = "DsaSigner"               and algo = "dsa"             or
    oc.getType().getName() = "DsaKeyPairGenerator"     and algo = "dsa-keygen"      or
    oc.getType().getName() = "GOST3410Signer"          and algo = "gost3410"        or
    oc.getType().getName() = "ElGamalEngine"           and algo = "elgamal"         or
    oc.getType().getName() = "ElGamalKeyPairGenerator" and algo = "elgamal-keygen"
  )
}

// ---------------------------------------------------------------------------
// Key Derivation Functions
// ---------------------------------------------------------------------------
predicate isBcKdfDetection(Expr call, string algo) {
  // PBKDF1
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "Pkcs5S1ParametersGenerator" and
    algo = "pbkdf1"
  )
  or
  // PBKDF2 — resolve digest
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "Pkcs5S2ParametersGenerator"
  |
    exists(string digestAlgo |
      bcDigestArg(oc.getArgument(0), digestAlgo) and algo = "pbkdf2-" + digestAlgo
    )
    or
    not exists(string d | bcDigestArg(oc.getArgument(0), d)) and algo = "pbkdf2"
  )
  or
  // HKDF — resolve digest
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "HkdfBytesGenerator"
  |
    exists(string digestAlgo |
      bcDigestArg(oc.getArgument(0), digestAlgo) and algo = "hkdf-" + digestAlgo
    )
    or
    not exists(string d | bcDigestArg(oc.getArgument(0), d)) and algo = "hkdf"
  )
  or
  // MGF1 — resolve digest
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "MGF1BytesGenerator"
  |
    exists(string digestAlgo |
      bcDigestArg(oc.getArgument(0), digestAlgo) and algo = "mgf1-" + digestAlgo
    )
    or
    not exists(string d | bcDigestArg(oc.getArgument(0), d)) and algo = "mgf1"
  )
  or
  // Concatenation KDF — resolve digest
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "ConcatenationKdfGenerator"
  |
    exists(string digestAlgo |
      bcDigestArg(oc.getArgument(0), digestAlgo) and algo = "concat-kdf-" + digestAlgo
    )
    or
    not exists(string d | bcDigestArg(oc.getArgument(0), d)) and algo = "concat-kdf"
  )
  or
  // KDF1 / KDF2 (X9.63 / ISO 18033) — resolve digest
  exists(ObjectCreation oc, string cls, string kdfName |
    oc = call and
    oc.getType().getName() = cls and
    (
      cls = "Kdf1BytesGenerator" and kdfName = "kdf1" or
      cls = "Kdf2BytesGenerator" and kdfName = "kdf2"
    )
  |
    exists(string digestAlgo |
      bcDigestArg(oc.getArgument(0), digestAlgo) and algo = kdfName + "-" + digestAlgo
    )
    or
    not exists(string d | bcDigestArg(oc.getArgument(0), d)) and algo = kdfName
  )
  or
  // KDF counter-mode
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "KdfCounterBytesGenerator" and
    algo = "kdf-counter"
  )
  or
  // SCrypt — static Generate method
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "Generate" and
    mc.getTarget().getDeclaringType().getName() = "SCrypt" and
    algo = "scrypt"
  )
  or
  // Argon2
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "Argon2BytesGenerator" and
    algo = "argon2"
  )
  or
  // BCrypt — static Generate / HashPassword methods
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["Generate", "HashPassword"] and
    mc.getTarget().getDeclaringType().getName() = "BCrypt" and
    algo = "bcrypt"
  )
}

// ---------------------------------------------------------------------------
// Cryptographically Secure Random Number Generation
// ---------------------------------------------------------------------------
predicate isBcRandomDetection(Expr call, string algo) {
  // SecureRandom constructor
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "SecureRandom" and
    algo = "csprng"
  )
  or
  // SecureRandom.GetInstance(string) factory
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "GetInstance" and
    mc.getTarget().getDeclaringType().getName() = "SecureRandom" and
    algo = "csprng"
  )
  or
  // DigestRandomGenerator(IDigest) — resolve underlying digest
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "DigestRandomGenerator"
  |
    exists(string digestAlgo |
      bcDigestArg(oc.getArgument(0), digestAlgo) and algo = "digest-prng-" + digestAlgo
    )
    or
    not exists(string d | bcDigestArg(oc.getArgument(0), d)) and algo = "digest-prng"
  )
  or
  // VmpcRandomGenerator and SP800SecureRandomBuilder
  exists(ObjectCreation oc |
    oc = call
  |
    oc.getType().getName() = "VmpcRandomGenerator"     and algo = "vmpc-prng"  or
    oc.getType().getName() = "SP800SecureRandomBuilder" and algo = "sp800-prng"
  )
}

// ---------------------------------------------------------------------------
// X.509 / PKI / PEM / PKCS
// ---------------------------------------------------------------------------
predicate isBcPkiDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call
  |
    oc.getType().getName() = "X509V1CertificateGenerator"  and algo = "x509v1-cert-gen"        or
    oc.getType().getName() = "X509V3CertificateGenerator"  and algo = "x509v3-cert-gen"        or
    oc.getType().getName() = "X509V2CrlGenerator"          and algo = "x509v2-crl-gen"         or
    oc.getType().getName() = "X509CertificateParser"       and algo = "x509-parse"             or
    oc.getType().getName() = "PkixCertPathBuilder"         and algo = "pkix-certpath-build"    or
    oc.getType().getName() = "PkixCertPathValidator"       and algo = "pkix-certpath-validate" or
    oc.getType().getName() = "Pkcs12Store"                 and algo = "pkcs12"                 or
    oc.getType().getName() = "PemReader"                   and algo = "pem-read"               or
    oc.getType().getName() = "PemWriter"                   and algo = "pem-write"              or
    oc.getType().getName() = "Pkcs10CertificationRequest"  and algo = "pkcs10-csr"             or
    oc.getType().getName() = "Pkcs8Generator"              and algo = "pkcs8-export"
  )
}

// ---------------------------------------------------------------------------
// Block cipher padding and buffered cipher wrappers
// ---------------------------------------------------------------------------
predicate isBcPaddingDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call
  |
    oc.getType().getName() = "Pkcs7Padding"       and algo = "padding-pkcs7"     or
    oc.getType().getName() = "ZeroBytePadding"    and algo = "padding-zerobyte"  or
    oc.getType().getName() = "X923Padding"        and algo = "padding-x923"      or
    oc.getType().getName() = "ISO10126d2Padding"  and algo = "padding-iso10126"  or
    oc.getType().getName() = "ISO7816d4Padding"   and algo = "padding-iso7816d4" or
    oc.getType().getName() = "TbcPadding"         and algo = "padding-tbc"
  )
  or
  // PaddedBufferedBlockCipher / BufferedBlockCipher — resolve the wrapped cipher
  exists(ObjectCreation oc, string wrapper |
    oc = call and
    oc.getType().getName() = wrapper and
    wrapper = ["PaddedBufferedBlockCipher", "BufferedBlockCipher"]
  |
    exists(string cipherAlgo |
      bcCipherEngineArg(oc.getArgument(0), cipherAlgo) and algo = cipherAlgo + "-buffered"
    )
    or
    not exists(string c | bcCipherEngineArg(oc.getArgument(0), c)) and algo = "buffered-cipher"
  )
}

// ---------------------------------------------------------------------------
// Key wrapping / key encapsulation of symmetric keys
// ---------------------------------------------------------------------------
predicate isBcKeyWrapDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call
  |
    oc.getType().getName() = "AesWrapEngine"       and algo = "aes-kw"       or
    oc.getType().getName() = "AesWrapPadEngine"    and algo = "aes-kwp"      or
    oc.getType().getName() = "DesEdeWrapEngine"    and algo = "3des-kw"      or
    oc.getType().getName() = "Rc2WrapEngine"       and algo = "rc2-kw"       or
    oc.getType().getName() = "CamelliaWrapEngine"  and algo = "camellia-kw"  or
    oc.getType().getName() = "SeedWrapEngine"      and algo = "seed-kw"      or
    oc.getType().getName() = "AriaWrapEngine"      and algo = "aria-kw"      or
    oc.getType().getName() = "AriaWrapPadEngine"   and algo = "aria-kwp"     or
    oc.getType().getName() = "DstU7624WrapEngine"  and algo = "kalyna-kw"    or
    oc.getType().getName() = "Gost28147WrapEngine" and algo = "gost28147-kw"
  )
  or
  // Rfc3394 / Rfc5649 generic wrappers — resolve the underlying cipher engine
  exists(ObjectCreation oc, string wrapper, string suffix |
    oc = call and
    oc.getType().getName() = wrapper and
    (
      wrapper = "Rfc3394WrapEngine" and suffix = "-kw" or
      wrapper = "Rfc5649WrapEngine" and suffix = "-kwp"
    )
  |
    exists(string cipherAlgo |
      bcCipherEngineArg(oc.getArgument(0), cipherAlgo) and algo = cipherAlgo + suffix
    )
    or
    not exists(string c | bcCipherEngineArg(oc.getArgument(0), c)) and
    (
      wrapper = "Rfc3394WrapEngine" and algo = "rfc3394-kw" or
      wrapper = "Rfc5649WrapEngine" and algo = "rfc5649-kwp"
    )
  )
  or
  // WrapperUtilities.GetWrapper("AESWRAP") — string-based factory
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "GetWrapper" and
    mc.getTarget().getDeclaringType().getName() = "WrapperUtilities" and
    algo = "keywrap:" + mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// Lightweight / NIST LWC AEAD ciphers and additional AEAD modes
// ---------------------------------------------------------------------------
predicate isBcLightweightAeadDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call
  |
    oc.getType().getName() = "AsconEngine"        and algo = "ascon"         or
    oc.getType().getName() = "ElephantEngine"     and algo = "elephant"      or
    oc.getType().getName() = "IsapEngine"         and algo = "isap"          or
    oc.getType().getName() = "PhotonBeetleEngine" and algo = "photon-beetle" or
    oc.getType().getName() = "SparkleEngine"      and algo = "schwaemm"      or
    oc.getType().getName() = "XoodyakEngine"      and algo = "xoodyak"       or
    oc.getType().getName() = "RomulusEngine"      and algo = "romulus"       or
    oc.getType().getName() = "TinyJambuEngine"    and algo = "tinyjambu"
  )
  or
  // GCM-SIV, and the DSTU / Ukrainian AEAD modes — resolve the wrapped cipher
  exists(ObjectCreation oc, string modeCls, string modeSuffix |
    oc = call and
    oc.getType().getName() = modeCls and
    (
      modeCls = "GcmSivBlockCipher" and modeSuffix = "-gcm-siv" or
      modeCls = "KCcmBlockCipher"   and modeSuffix = "-kccm"    or
      modeCls = "KGcmBlockCipher"   and modeSuffix = "-kgcm"    or
      modeCls = "KXtsBlockCipher"   and modeSuffix = "-kxts"    or
      modeCls = "XtsBlockCipher"    and modeSuffix = "-xts"     or
      modeCls = "G3413CbcBlockCipher" and modeSuffix = "-g3413-cbc" or
      modeCls = "G3413CtrBlockCipher" and modeSuffix = "-g3413-ctr"
    )
  |
    exists(string cipherAlgo |
      bcCipherEngineArg(oc.getArgument(0), cipherAlgo) and algo = cipherAlgo + modeSuffix
    )
    or
    not exists(string c | bcCipherEngineArg(oc.getArgument(0), c)) and
    algo = modeSuffix.suffix(1) + "-mode"
  )
}

// ---------------------------------------------------------------------------
// Post-quantum algorithms (Org.BouncyCastle.Pqc.Crypto.*)
// ---------------------------------------------------------------------------
predicate isBcPqcDetection(Expr call, string algo) {
  exists(ObjectCreation oc, string cls |
    oc = call and
    cls = oc.getType().getName()
  |
    // ML-KEM / CRYSTALS-Kyber (FIPS 203)
    cls = ["MLKemGenerator", "MLKemExtractor", "MLKemKeyPairGenerator"] and algo = "ml-kem" or
    cls = ["KyberKemGenerator", "KyberKemExtractor", "KyberKeyPairGenerator"] and algo = "kyber" or
    // ML-DSA / CRYSTALS-Dilithium (FIPS 204)
    cls = ["MLDsaSigner", "MLDsaKeyPairGenerator"] and algo = "ml-dsa" or
    cls = ["DilithiumSigner", "DilithiumKeyPairGenerator"] and algo = "dilithium" or
    // SLH-DSA / SPHINCS+ (FIPS 205)
    cls = ["SlhDsaSigner", "SlhDsaKeyPairGenerator"] and algo = "slh-dsa" or
    cls = ["SphincsPlusSigner", "SphincsPlusKeyPairGenerator", "SphincsSigner"] and algo = "sphincs-plus" or
    // Other NIST round candidates and stateful hash-based signatures
    cls = ["FalconSigner", "FalconKeyPairGenerator"] and algo = "falcon" or
    cls = ["NtruKemGenerator", "NtruKemExtractor", "NtruKeyPairGenerator"] and algo = "ntru" or
    cls = ["NtruLPRimeKemGenerator", "SntruPrimeKemGenerator"] and algo = "ntru-prime" or
    cls = ["FrodoKemGenerator", "FrodoKemExtractor", "FrodoKeyPairGenerator"] and algo = "frodokem" or
    cls = ["SaberKemGenerator", "SaberKemExtractor", "SaberKeyPairGenerator"] and algo = "saber" or
    cls = ["BikeKemGenerator", "BikeKemExtractor", "BikeKeyPairGenerator"] and algo = "bike" or
    cls = ["HqcKemGenerator", "HqcKemExtractor", "HqcKeyPairGenerator"] and algo = "hqc" or
    cls = ["CmceKemGenerator", "CmceKemExtractor", "CmceKeyPairGenerator"] and algo = "classic-mceliece" or
    cls = ["PicnicSigner", "PicnicKeyPairGenerator"] and algo = "picnic" or
    cls = ["RainbowSigner", "RainbowKeyPairGenerator"] and algo = "rainbow" or
    cls = ["GeMSSSigner", "GeMSSKeyPairGenerator"] and algo = "gemss" or
    cls = ["XmssSigner", "XmssKeyPairGenerator"] and algo = "xmss" or
    cls = ["XmssMTSigner", "XmssMTKeyPairGenerator"] and algo = "xmss-mt" or
    cls = ["LmsSigner", "LmsKeyPairGenerator", "HssSigner", "HssKeyPairGenerator"] and algo = "lms" or
    cls = ["NHAgreement", "NHSecretKeyProcessor", "NHKeyPairGenerator"] and algo = "newhope" or
    cls = ["SikeKemGenerator", "SikeKeyPairGenerator"] and algo = "sike"
  )
}

// ---------------------------------------------------------------------------
// Named elliptic curves
// ---------------------------------------------------------------------------
predicate isBcCurveDetection(Expr call, string algo) {
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = ["GetByName", "GetByOid", "GetOid"] and
    mc.getTarget().getDeclaringType().getName() = [
      "ECNamedCurveTable", "CustomNamedCurves", "SecNamedCurves", "NistNamedCurves",
      "X962NamedCurves", "TeleTrusTNamedCurves", "AnssiNamedCurves", "GMNamedCurves",
      "ECGost3410NamedCurves"
    ] and
    algo = "ec-curve:" + mc.getArgument(0).(StringLiteral).getValue().toLowerCase()
  )
}

// ---------------------------------------------------------------------------
// Explicit key strengths supplied to key-pair generators
// ---------------------------------------------------------------------------
predicate isBcKeyStrengthDetection(Expr call, string algo) {
  // new RsaKeyGenerationParameters(publicExponent, random, strength, certainty)
  exists(ObjectCreation oc |
    oc = call and
    oc.getType().getName() = "RsaKeyGenerationParameters"
  |
    exists(string strength |
      strength = oc.getArgument(2).(Literal).getValue() and
      oc.getArgument(2).getType() instanceof IntType and
      algo = "rsa-" + strength + "-keygen"
    )
    or
    not (oc.getArgument(2).getType() instanceof IntType and exists(oc.getArgument(2).(Literal))) and
    algo = "rsa-keygen"
  )
  or
  // new DsaParametersGenerator(...).Init(size, certainty, random)
  exists(MethodCall mc |
    mc = call and
    mc.getTarget().getName() = "Init" and
    mc.getTarget().getDeclaringType().getName() =
      ["DsaParametersGenerator", "DHParametersGenerator", "ElGamalParametersGenerator"]
  |
    exists(string strength |
      strength = mc.getArgument(0).(Literal).getValue() and
      mc.getArgument(0).getType() instanceof IntType and
      algo = "dl-params-" + strength
    )
    or
    not (mc.getArgument(0).getType() instanceof IntType and exists(mc.getArgument(0).(Literal))) and
    algo = "dl-params"
  )
}

// ---------------------------------------------------------------------------
// Integrated encryption schemes
// ---------------------------------------------------------------------------
predicate isBcIesDetection(Expr call, string algo) {
  exists(ObjectCreation oc |
    oc = call
  |
    oc.getType().getName() = "IesEngine"           and algo = "ies"          or
    oc.getType().getName() = "EthereumIesEngine"   and algo = "ecies-eth"    or
    oc.getType().getName() = "EciesEngine"         and algo = "ecies"        or
    oc.getType().getName() = "IesWithCipherParameters" and algo = "ies"      or
    oc.getType().getName() = "Sm2KeyExchange"      and algo = "sm2-dh"
  )
}

// ---------------------------------------------------------------------------
// Higher-level protocol layers: TLS, CMS and OpenPGP
// ---------------------------------------------------------------------------
predicate isBcProtocolDetection(Expr call, string algo) {
  exists(ObjectCreation oc, string cls |
    oc = call and
    cls = oc.getType().getName()
  |
    cls = ["TlsClientProtocol", "TlsServerProtocol"]   and algo = "tls"      or
    cls = ["DtlsClientProtocol", "DtlsServerProtocol"] and algo = "dtls"     or
    cls = "CmsSignedDataGenerator"                     and algo = "cms-sign" or
    cls = "CmsEnvelopedDataGenerator"                  and algo = "cms-encrypt" or
    cls = "CmsSignedData"                              and algo = "cms-signed" or
    cls = "CmsEnvelopedData"                           and algo = "cms-enveloped" or
    cls = "PgpEncryptedDataGenerator"                  and algo = "pgp-encrypt" or
    cls = "PgpSignatureGenerator"                      and algo = "pgp-sign"    or
    cls = "PgpKeyRingGenerator"                        and algo = "pgp-keygen"  or
    cls = "PgpKeyPair"                                 and algo = "pgp-keypair" or
    cls = "OcspReqGenerator"                           and algo = "ocsp-request" or
    cls = "TimeStampRequestGenerator"                  and algo = "rfc3161-timestamp"
  )
}

// =============================================================================
// Main query
// =============================================================================

from Expr call, string algo, string api
where
  api = "Org.BouncyCastle" and
  (
    isBcHashDetection(call, algo) or
    isBcMacDetection(call, algo) or
    isBcSymmetricEngineDetection(call, algo) or
    isBcModeDetection(call, algo) or
    isBcStreamCipherDetection(call, algo) or
    isBcRsaDetection(call, algo) or
    isBcEcDetection(call, algo) or
    isBcDsaElGamalDetection(call, algo) or
    isBcKdfDetection(call, algo) or
    isBcRandomDetection(call, algo) or
    isBcPkiDetection(call, algo) or
    isBcPaddingDetection(call, algo) or
    isBcKeyWrapDetection(call, algo) or
    isBcLightweightAeadDetection(call, algo) or
    isBcPqcDetection(call, algo) or
    isBcCurveDetection(call, algo) or
    isBcKeyStrengthDetection(call, algo) or
    isBcIesDetection(call, algo) or
    isBcProtocolDetection(call, algo)
  )
select call, "algo=" + algo + ", api=" + api
