// Test suite for MicrosoftIdentityModelJsonWebTokens.ql
// Every method exercises at least one detection path in the QL query.
// type-stubs.cs provides Microsoft.IdentityModel.Tokens and
// Microsoft.IdentityModel.JsonWebTokens declarations for the CodeQL extractor.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CbomTestSuite.Csharp
{
    // =========================================================================
    // JsonWebTokenHandler — async-first handler operations
    // Expected: jwt-create, jwt-validate, jwt-read
    // =========================================================================
    public static class MicrosoftJwtHandlerTests
    {
        // Create token with HMAC signing (sync)
        public static string CreateHmacSignedToken()
        {
            var key    = new SymmetricSecurityKey(new byte[32]);
            var creds  = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var handler = new JsonWebTokenHandler();

            return handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer            = "https://example.com",
                Audience          = "api",
                Expires           = DateTime.UtcNow.AddHours(1),
                SigningCredentials = creds,
            });
        }

        // Create token with RSA signing (async)
        public static async Task<string> CreateRsaSignedTokenAsync()
        {
            using var rsa  = RSA.Create(2048);
            var key        = new RsaSecurityKey(rsa);
            var creds      = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
            var handler    = new JsonWebTokenHandler();

            return await handler.CreateTokenAsync(new SecurityTokenDescriptor
            {
                Issuer            = "https://example.com",
                Audience          = "api",
                Expires           = DateTime.UtcNow.AddHours(1),
                SigningCredentials = creds,
            });
        }

        // Create JWE (signed + encrypted)
        public static string CreateEncryptedToken()
        {
            var sigKey  = new SymmetricSecurityKey(new byte[32]);
            var encKey  = new SymmetricSecurityKey(new byte[32]);
            var handler = new JsonWebTokenHandler();

            return handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer                = "https://example.com",
                Expires               = DateTime.UtcNow.AddHours(1),
                SigningCredentials    = new SigningCredentials(sigKey, SecurityAlgorithms.HmacSha256),
                EncryptingCredentials = new EncryptingCredentials(encKey,
                    SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512),
            });
        }

        // Validate token (sync overload)
        public static TokenValidationResult ValidateTokenSync(string token, SecurityKey signingKey) =>
            new JsonWebTokenHandler().ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer           = true,
                ValidIssuer              = "https://example.com",
                ValidateAudience         = true,
                ValidAudience            = "api",
                ValidateIssuerSigningKey = true,
                IssuerSigningKey         = signingKey,
            });

        // Validate token (async — preferred)
        public static async Task<TokenValidationResult> ValidateTokenAsync(string token, SecurityKey signingKey)
        {
            var handler = new JsonWebTokenHandler();
            return await handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidateIssuer           = true,
                ValidIssuer              = "https://example.com",
                ValidateAudience         = true,
                ValidAudience            = "api",
                ValidateIssuerSigningKey = true,
                IssuerSigningKey         = signingKey,
            });
        }

        // Parse without validation (insecure — captured for CBOM inventory)
        public static JsonWebToken ParseUnsafe(string token)
            => new JsonWebTokenHandler().ReadJsonWebToken(token);

        public static bool CanRead(string token)
            => new JsonWebTokenHandler().CanReadToken(token);
    }

    // =========================================================================
    // Security key construction
    // Expected: symmetric-key, rsa-key, ecdsa-key, x509-key, jwk, jwks
    // =========================================================================
    public static class MicrosoftJwtKeyTests
    {
        public static SymmetricSecurityKey MakeSymmetricKey(byte[] raw)
            => new SymmetricSecurityKey(raw);

        public static RsaSecurityKey MakeRsaKey()
        {
            using var rsa = RSA.Create(2048);
            return new RsaSecurityKey(rsa);
        }

        public static RsaSecurityKey MakeRsaKeyFromParams()
        {
            using var rsa = RSA.Create(2048);
            return new RsaSecurityKey(rsa.ExportParameters(false));
        }

        public static ECDsaSecurityKey MakeEcdsaKeyP384()
        {
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            return new ECDsaSecurityKey(ec);
        }

        public static X509SecurityKey MakeX509Key(X509Certificate2 cert)
            => new X509SecurityKey(cert);

        public static JsonWebKey MakeJwkFromJson()
            => new JsonWebKey(@"{""kty"":""EC"",""crv"":""P-256"",""use"":""sig""}");

        public static JsonWebKey MakeEmptyJwk()
            => new JsonWebKey();

        public static JsonWebKeySet MakeJwksFromJson()
            => new JsonWebKeySet(@"{""keys"":[]}");

        public static JsonWebKeySet MakeJwksViaCreate()
            => JsonWebKeySet.Create(@"{""keys"":[]}");
    }

    // =========================================================================
    // SigningCredentials — covers all signing algorithm constants
    // Expected: jwt-signing-{algo} for each, jwt-signing-credentials as fallback
    // =========================================================================
    public static class MicrosoftJwtSigningTests
    {
        static readonly SymmetricSecurityKey HmacKey256 = new SymmetricSecurityKey(new byte[32]);
        static readonly SymmetricSecurityKey HmacKey512 = new SymmetricSecurityKey(new byte[64]);

        // HMAC-based
        public static SigningCredentials Hs256() =>
            new SigningCredentials(HmacKey256, SecurityAlgorithms.HmacSha256);

        public static SigningCredentials Hs384() =>
            new SigningCredentials(HmacKey256, SecurityAlgorithms.HmacSha384);

        public static SigningCredentials Hs512() =>
            new SigningCredentials(HmacKey512, SecurityAlgorithms.HmacSha512);

        // RSA PKCS#1 v1.5
        public static SigningCredentials Rs256()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
        }

        public static SigningCredentials Rs384()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha384);
        }

        public static SigningCredentials Rs512()
        {
            using var rsa = RSA.Create(4096);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha512);
        }

        // RSA-PSS
        public static SigningCredentials Ps256()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSsaPssSha256);
        }

        public static SigningCredentials Ps384()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSsaPssSha384);
        }

        public static SigningCredentials Ps512()
        {
            using var rsa = RSA.Create(4096);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSsaPssSha512);
        }

        // ECDSA
        public static SigningCredentials Es256()
        {
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new SigningCredentials(new ECDsaSecurityKey(ec), SecurityAlgorithms.EcdsaSha256);
        }

        public static SigningCredentials Es384()
        {
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            return new SigningCredentials(new ECDsaSecurityKey(ec), SecurityAlgorithms.EcdsaSha384);
        }

        public static SigningCredentials Es512()
        {
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP521);
            return new SigningCredentials(new ECDsaSecurityKey(ec), SecurityAlgorithms.EcdsaSha512);
        }

        // Fallback — algorithm not statically resolvable
        public static SigningCredentials UnknownAlgo(SecurityKey key, string alg)
            => new SigningCredentials(key, alg);

        // 3-argument constructor — explicit digest algorithm
        public static SigningCredentials Hs384WithDigest() =>
            new SigningCredentials(HmacKey256, SecurityAlgorithms.HmacSha384, SecurityAlgorithms.Sha384);

        public static SigningCredentials Rs384WithDigest()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha384, SecurityAlgorithms.Sha384);
        }

        public static SigningCredentials Ps512WithDigest()
        {
            using var rsa = RSA.Create(4096);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSsaPssSha512, SecurityAlgorithms.Sha512);
        }

        public static SigningCredentials Es512WithDigest()
        {
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP521);
            return new SigningCredentials(new ECDsaSecurityKey(ec), SecurityAlgorithms.EcdsaSha512, SecurityAlgorithms.Sha512);
        }
    }

    // =========================================================================
    // EncryptingCredentials — JWE key-wrap + content encryption algorithm pairs
    // Expected: jwt-jwe-{kw}-{enc}, jwt-encrypting-credentials as fallback
    // =========================================================================
    public static class MicrosoftJwtEncryptingTests
    {
        static SymmetricSecurityKey SymKey(int bytes) => new SymmetricSecurityKey(new byte[bytes]);

        public static EncryptingCredentials A256KwA256Gcm() =>
            new EncryptingCredentials(SymKey(32),
                SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256Gcm);

        public static EncryptingCredentials A128KwA128CbcHs256() =>
            new EncryptingCredentials(SymKey(16),
                SecurityAlgorithms.Aes128KW, SecurityAlgorithms.Aes128CbcHmacSha256);

        public static EncryptingCredentials A192KwA192Gcm() =>
            new EncryptingCredentials(SymKey(24),
                SecurityAlgorithms.Aes192KW, SecurityAlgorithms.Aes192Gcm);

        public static EncryptingCredentials RsaOaepA128Gcm()
        {
            using var rsa = RSA.Create(2048);
            return new EncryptingCredentials(new RsaSecurityKey(rsa),
                SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128Gcm);
        }

        public static EncryptingCredentials RsaOaep256A256CbcHs512()
        {
            using var rsa = RSA.Create(2048);
            return new EncryptingCredentials(new RsaSecurityKey(rsa),
                SecurityAlgorithms.RsaOAEP256, SecurityAlgorithms.Aes256CbcHmacSha512);
        }

        public static EncryptingCredentials Fallback(SecurityKey key, string kw, string enc)
            => new EncryptingCredentials(key, kw, enc);

        // Only the key-wrap algorithm is statically resolvable
        public static EncryptingCredentials KwOnly(SecurityKey key, string enc) =>
            new EncryptingCredentials(key, SecurityAlgorithms.Aes256KW, enc);

        // Only the content-encryption algorithm is statically resolvable
        public static EncryptingCredentials EncOnly(SecurityKey key, string kw) =>
            new EncryptingCredentials(key, kw, SecurityAlgorithms.Aes256Gcm);
    }

    // =========================================================================
    // SecurityAlgorithms constant references
    // Expected: one result per constant, using the mapped algo label
    // =========================================================================
    public static class MicrosoftJwtAlgorithmsTests
    {
        // HMAC
        public static string Hs256Const()  => SecurityAlgorithms.HmacSha256;
        public static string Hs384Const()  => SecurityAlgorithms.HmacSha384;
        public static string Hs512Const()  => SecurityAlgorithms.HmacSha512;
        public static string Hs256SigConst() => SecurityAlgorithms.HmacSha256Signature;

        // RSA PKCS#1 v1.5
        public static string Rs256Const()  => SecurityAlgorithms.RsaSha256;
        public static string Rs384Const()  => SecurityAlgorithms.RsaSha384;
        public static string Rs512Const()  => SecurityAlgorithms.RsaSha512;

        // RSA-PSS
        public static string Ps256Const()  => SecurityAlgorithms.RsaSsaPssSha256;
        public static string Ps384Const()  => SecurityAlgorithms.RsaSsaPssSha384;
        public static string Ps512Const()  => SecurityAlgorithms.RsaSsaPssSha512;

        // ECDSA
        public static string Es256Const()  => SecurityAlgorithms.EcdsaSha256;
        public static string Es384Const()  => SecurityAlgorithms.EcdsaSha384;
        public static string Es512Const()  => SecurityAlgorithms.EcdsaSha512;

        // AES key wrap
        public static string A128KwConst() => SecurityAlgorithms.Aes128KW;
        public static string A192KwConst() => SecurityAlgorithms.Aes192KW;
        public static string A256KwConst() => SecurityAlgorithms.Aes256KW;

        // RSA key agreement
        public static string RsaOaepConst()    => SecurityAlgorithms.RsaOAEP;
        public static string RsaOaep256Const() => SecurityAlgorithms.RsaOAEP256;
        public static string RsaPkcs1Const()   => SecurityAlgorithms.RsaPKCS1;

        // AES-CBC-HMAC content encryption
        public static string A128CbcHs256Const() => SecurityAlgorithms.Aes128CbcHmacSha256;
        public static string A192CbcHs384Const() => SecurityAlgorithms.Aes192CbcHmacSha384;
        public static string A256CbcHs512Const() => SecurityAlgorithms.Aes256CbcHmacSha512;

        // AES-GCM content encryption
        public static string A128GcmConst() => SecurityAlgorithms.Aes128Gcm;
        public static string A192GcmConst() => SecurityAlgorithms.Aes192Gcm;
        public static string A256GcmConst() => SecurityAlgorithms.Aes256Gcm;
    }

    // =========================================================================
    // Microsoft.IdentityModel.JsonWebTokens
    // Algorithm identifiers previously missing from the inventory
    // Expected algo tags: none, eddsa, ecdh-es, ecdh-es-a128kw, ecdh-es-a256kw,
    //                     sha256, sha384, sha512, es256, ps512, es256k
    // =========================================================================
    public static class JsonWebTokenExtendedAlgorithmTests
    {
        public static string NoneAlgorithm()   => SecurityAlgorithms.None;
        // No SecurityAlgorithms.EdDsa constant exists in the real library; EdDSA is
        // only usable as the raw JWA string literal.
        public static string EdDsa()           => "EdDSA";
        public static string EcdhEs()          => SecurityAlgorithms.EcdhEs;
        public static string EcdhEsA128Kw()    => SecurityAlgorithms.EcdhEsA128kw;
        public static string EcdhEsA192Kw()    => SecurityAlgorithms.EcdhEsA192kw;
        public static string EcdhEsA256Kw()    => SecurityAlgorithms.EcdhEsA256kw;
        public static string Sha256Digest()    => SecurityAlgorithms.Sha256;
        public static string Sha384Digest()    => SecurityAlgorithms.Sha384;
        public static string Sha512Digest()    => SecurityAlgorithms.Sha512;
        public static string Sha256DigestUri() => SecurityAlgorithms.Sha256Digest;
        public static string EcdsaSignatureUri() => SecurityAlgorithms.EcdsaSha256Signature;
        public static string PssSignatureUri()   => SecurityAlgorithms.RsaSsaPssSha512Signature;

        public static SigningCredentials NoneCredentials(SecurityKey key) =>
            new SigningCredentials(key, "none");

        public static SigningCredentials EdDsaCredentials(SecurityKey key) =>
            new SigningCredentials(key, "EdDSA");

        public static SigningCredentials Es256KCredentials(SecurityKey key) =>
            new SigningCredentials(key, "ES256K");

        public static EncryptingCredentials EcdhEsCredentials(SecurityKey key) =>
            new EncryptingCredentials(key, "ECDH-ES+A256KW", "A256GCM");

        public static EncryptingCredentials DirectCredentials(SecurityKey key) =>
            new EncryptingCredentials(key, "dir", "A128CBC-HS256");
    }

    // =========================================================================
    // Remaining XML-DSig style signature URIs
    // Expected algo tags: es384, es512, ps256, ps384
    // =========================================================================
    public static class JsonWebTokenSignatureUriTests
    {
        public static string EcdsaSha384Uri()   => SecurityAlgorithms.EcdsaSha384Signature;
        public static string EcdsaSha512Uri()   => SecurityAlgorithms.EcdsaSha512Signature;
        public static string PssSha256Uri()     => SecurityAlgorithms.RsaSsaPssSha256Signature;
        public static string PssSha384Uri()     => SecurityAlgorithms.RsaSsaPssSha384Signature;
        public static string Sha384DigestUri()  => SecurityAlgorithms.Sha384Digest;
        public static string Sha512DigestUri()  => SecurityAlgorithms.Sha512Digest;

        public static EncryptingCredentials EcdhEsA192KwCredentials(SecurityKey key) =>
            new EncryptingCredentials(key, "ECDH-ES+A192KW", "A192GCM");
    }

    // =========================================================================
    // Remaining XML-DSig style signature URIs
    // Expected algo tags: es384, es512, ps256, ps384, sha384, sha512
    // =========================================================================
    public static class MicrosoftJwtAdditionalCoverageTests
    {
        public static string MlDsa44() => SecurityAlgorithms.MlDsa44;
        public static string MlDsa65() => SecurityAlgorithms.MlDsa65;
        public static string MlDsa87() => SecurityAlgorithms.MlDsa87;
        public static string Aes128Xml() => SecurityAlgorithms.Aes128Encryption;
        public static string Aes192Xml() => SecurityAlgorithms.Aes192Encryption;
        public static string Aes256Xml() => SecurityAlgorithms.Aes256Encryption;
        public static string DesXml() => SecurityAlgorithms.DesEncryption;
        public static string Aes128XmlKeyWrap() => SecurityAlgorithms.Aes128KeyWrap;
        public static string RsaOaepXmlKeyWrap() => SecurityAlgorithms.RsaOaepKeyWrap;
        public static string Ripemd160Xml() => SecurityAlgorithms.Ripemd160Digest;
        public static string ExclusiveC14n() => SecurityAlgorithms.ExclusiveC14n;
        public static string ExclusiveC14nComments() => SecurityAlgorithms.ExclusiveC14nWithComments;
        public static string EnvelopedSignature() => SecurityAlgorithms.EnvelopedSignature;

        public static SigningCredentials SigningWithDigest(SecurityKey key) =>
            new SigningCredentials(key, SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256);

        public static JwtSecurityToken WriteToken(JwtSecurityToken token) =>
            new JwtSecurityTokenHandler().CreateJwtSecurityToken(new SecurityTokenDescriptor());

        public static string CreateEncodedJwt() =>
            new JwtSecurityTokenHandler().CreateEncodedJwt(new SecurityTokenDescriptor());

        public static string WriteEncodedToken(SecurityToken token) =>
            new JwtSecurityTokenHandler().WriteToken(token);

        public static string DecryptToken(JwtSecurityToken token) =>
            new JwtSecurityTokenHandler().DecryptToken(token, new TokenValidationParameters());

        public static bool ValidateSignature(string token) =>
            new JwtSecurityTokenHandler().ValidateSignature(token, new TokenValidationParameters());
    }

    // =========================================================================
    // Lower-level Microsoft.IdentityModel cryptographic providers
    // Expected: jwt-provider-signing, jwt-provider-verifying, jwt-provider-key-wrap,
    //   jwt-provider-key-unwrap, jwt-provider-authenticated-encryption, jwt-provider-hash,
    //   jwt-sign, jwt-verify, jwt-key-wrap, jwt-key-unwrap,
    //   jwt-authenticated-encrypt, jwt-authenticated-decrypt, jwt-hash
    // =========================================================================
    public static class MicrosoftJwtCryptoProviderTests
    {
        static readonly SecurityKey Key = new SymmetricSecurityKey(new byte[32]);

        public static SignatureProvider CreateForSigning() =>
            CryptoProviderFactory.Default.CreateForSigning(Key, SecurityAlgorithms.HmacSha256);

        public static SignatureProvider CreateForVerifying() =>
            CryptoProviderFactory.Default.CreateForVerifying(Key, SecurityAlgorithms.HmacSha256);

        public static KeyWrapProvider CreateKeyWrapProviderForWrapping() =>
            CryptoProviderFactory.Default.CreateKeyWrapProviderForWrapping(Key, SecurityAlgorithms.Aes256KW);

        public static KeyWrapProvider CreateKeyWrapProviderForUnwrapping() =>
            CryptoProviderFactory.Default.CreateKeyWrapProviderForUnwrapping(Key, SecurityAlgorithms.Aes256KW);

        public static AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider() =>
            CryptoProviderFactory.Default.CreateAuthenticatedEncryptionProvider(Key, SecurityAlgorithms.Aes256CbcHmacSha512);

        public static HashAlgorithmProvider CreateHashAlgorithm() =>
            CryptoProviderFactory.Default.CreateHashAlgorithm(SecurityAlgorithms.Sha256);

        public static byte[] Sign(SignatureProvider provider, byte[] input) => provider.Sign(input);
        public static bool Verify(SignatureProvider provider, byte[] input, byte[] signature) => provider.Verify(input, signature);

        public static byte[] WrapKey(KeyWrapProvider provider, byte[] keyToWrap) => provider.WrapKey(keyToWrap);
        public static byte[] UnwrapKey(KeyWrapProvider provider, byte[] wrappedKey) => provider.UnwrapKey(wrappedKey);

        public static byte[] Encrypt(AuthenticatedEncryptionProvider provider, byte[] plaintext, byte[] aad) =>
            provider.Encrypt(plaintext, aad, out _, out _);
        public static byte[] Decrypt(AuthenticatedEncryptionProvider provider, byte[] ciphertext, byte[] aad, byte[] iv, byte[] tag) =>
            provider.Decrypt(ciphertext, aad, iv, tag);

        public static HashAlgorithmProvider CreateHashViaStatic() =>
            HashAlgorithmProvider.CreateHash(SecurityAlgorithms.Sha256);
        public static byte[] Hash(HashAlgorithmProvider provider, byte[] input) => provider.Hash(input);
    }

}
