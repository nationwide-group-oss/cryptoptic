// Test suite for SystemIdentityModelJwt.ql
// Every method exercises at least one detection path in the QL query.
// type-stubs.cs provides Microsoft.IdentityModel.Tokens, System.IdentityModel.Tokens.Jwt,
// and Microsoft.IdentityModel.JsonWebTokens declarations for the CodeQL extractor.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace CbomTestSuite.Csharp
{
    // =========================================================================
    // Security key construction
    // Expected: symmetric-key, rsa-key, ecdsa-key, x509-key, jwk, jwks
    // =========================================================================
    public static class SecurityKeyTests
    {
        public static SymmetricSecurityKey CreateSymmetricKey()
            => new SymmetricSecurityKey(new byte[32]);

        public static RsaSecurityKey CreateRsaKey()
        {
            using var rsa = RSA.Create(2048);
            return new RsaSecurityKey(rsa);
        }

        public static RsaSecurityKey CreateRsaKeyFromParams()
        {
            using var rsa = RSA.Create(2048);
            return new RsaSecurityKey(rsa.ExportParameters(true));
        }

        public static ECDsaSecurityKey CreateEcdsaKey()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new ECDsaSecurityKey(ecdsa);
        }

        public static JsonWebKey CreateJwk()
            => new JsonWebKey(@"{""kty"":""RSA"",""use"":""sig""}");

        public static JsonWebKey CreateEmptyJwk()
            => new JsonWebKey();

        public static JsonWebKeySet CreateJwks()
            => new JsonWebKeySet(@"{""keys"":[]}");

        public static JsonWebKeySet CreateJwksFromUrl()
            => JsonWebKeySet.Create(@"{""keys"":[]}");
        public static X509SecurityKey CreateX509Key()
            => new X509SecurityKey(new X509Certificate2("cert.pfx", "password"));    }

    // =========================================================================
    // SigningCredentials — key + signing algorithm
    // Expected: jwt-signing-hs256, jwt-signing-rs256, jwt-signing-ps256,
    //           jwt-signing-es256, jwt-signing-credentials
    // =========================================================================
    public static class SigningCredentialsTests
    {
        static readonly SymmetricSecurityKey HmacKey = new SymmetricSecurityKey(new byte[32]);

        // Algorithm from SecurityAlgorithms field (data flow via local variable)
        public static SigningCredentials CreateHs256Creds()
        {
            var algo = SecurityAlgorithms.HmacSha256;
            return new SigningCredentials(HmacKey, algo);
        }

        // Algorithm from SecurityAlgorithms field (inline literal)
        public static SigningCredentials CreateHs384Creds()
            => new SigningCredentials(HmacKey, SecurityAlgorithms.HmacSha384);

        public static SigningCredentials CreateHs512Creds()
            => new SigningCredentials(HmacKey, SecurityAlgorithms.HmacSha512);

        public static SigningCredentials CreateRs256Creds()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
        }

        public static SigningCredentials CreateRs384Creds()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha384);
        }

        public static SigningCredentials CreateRs512Creds()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha512);
        }

        public static SigningCredentials CreatePs256Creds()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSsaPssSha256);
        }

        public static SigningCredentials CreatePs384Creds()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSsaPssSha384);
        }

        public static SigningCredentials CreatePs512Creds()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSsaPssSha512);
        }

        public static SigningCredentials CreateEs256Creds()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256);
        }

        public static SigningCredentials CreateEs384Creds()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            return new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha384);
        }

        public static SigningCredentials CreateEs512Creds()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);
            return new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha512);
        }

        // Algorithm as string literal — fallback path
        public static SigningCredentials CreateRs256CredsLiteral()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), "RS256");
        }

        // Algorithm not statically resolvable — fallback jwt-signing-credentials
        public static SigningCredentials CreateCredsUnknownAlgo(SecurityKey key, string algorithm)
            => new SigningCredentials(key, algorithm);

        // 3-argument constructor — explicit digest algorithm alongside the signing algorithm
        public static SigningCredentials CreateHs256WithDigest()
            => new SigningCredentials(HmacKey, SecurityAlgorithms.HmacSha256, SecurityAlgorithms.Sha256);

        public static SigningCredentials CreateRs256WithDigest()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha384);
        }

        public static SigningCredentials CreatePs256WithDigest()
        {
            using var rsa = RSA.Create(2048);
            return new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.Sha256);
        }

        public static SigningCredentials CreateEs256WithDigest()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.Sha256);
        }
    }

    // =========================================================================
    // EncryptingCredentials — JWE key wrap + content encryption
    // Expected: jwt-jwe-rsa-oaep-a256gcm, jwt-jwe-a256kw-a256cbc-hs512,
    //           jwt-encrypting-credentials
    // =========================================================================
    public static class EncryptingCredentialsTests
    {
        public static EncryptingCredentials CreateRsaOaepA256Gcm()
        {
            using var rsa = RSA.Create(2048);
            return new EncryptingCredentials(
                new RsaSecurityKey(rsa),
                SecurityAlgorithms.RsaOAEP,
                SecurityAlgorithms.Aes256Gcm);
        }

        public static EncryptingCredentials CreateRsaOaep256A128CbcHs256()
        {
            using var rsa = RSA.Create(2048);
            return new EncryptingCredentials(
                new RsaSecurityKey(rsa),
                SecurityAlgorithms.RsaOAEP256,
                SecurityAlgorithms.Aes128CbcHmacSha256);
        }

        public static EncryptingCredentials CreateA256KwA256CbcHs512()
        {
            var key = new SymmetricSecurityKey(new byte[32]);
            return new EncryptingCredentials(key,
                SecurityAlgorithms.Aes256KW,
                SecurityAlgorithms.Aes256CbcHmacSha512);
        }

        public static EncryptingCredentials CreateA128KwA128Gcm()
        {
            var key = new SymmetricSecurityKey(new byte[16]);
            return new EncryptingCredentials(key,
                SecurityAlgorithms.Aes128KW,
                SecurityAlgorithms.Aes128Gcm);
        }

        // Algorithm not statically resolvable — fallback jwt-encrypting-credentials
        public static EncryptingCredentials CreateCredsUnknown(SecurityKey key, string kw, string enc)
            => new EncryptingCredentials(key, kw, enc);

        public static EncryptingCredentials CreateRsaPkcs1A128Gcm()
        {
            using var rsa = RSA.Create(2048);
            return new EncryptingCredentials(
                new RsaSecurityKey(rsa),
                SecurityAlgorithms.RsaPKCS1,
                SecurityAlgorithms.Aes128Gcm);
        }

        public static EncryptingCredentials CreateA192KwA192CbcHs384()
        {
            var key = new SymmetricSecurityKey(new byte[24]);
            return new EncryptingCredentials(key,
                SecurityAlgorithms.Aes192KW,
                SecurityAlgorithms.Aes192CbcHmacSha384);
        }

        // Only the key-wrap algorithm is statically resolvable
        public static EncryptingCredentials CreateKwOnly(SecurityKey key, string enc)
            => new EncryptingCredentials(key, SecurityAlgorithms.Aes192KW, enc);

        // Only the content-encryption algorithm is statically resolvable
        public static EncryptingCredentials CreateEncOnly(SecurityKey key, string kw)
            => new EncryptingCredentials(key, kw, SecurityAlgorithms.Aes192CbcHmacSha384);
    }

    // =========================================================================
    // JwtSecurityTokenHandler — classic handler (System.IdentityModel.Tokens.Jwt)
    // Expected: jwt-create, jwt-write, jwt-validate, jwt-read
    // =========================================================================
    public static class JwtHandlerTests
    {
        static TokenValidationParameters MakeValidationParams(SecurityKey signingKey) =>
            new TokenValidationParameters
            {
                ValidateIssuer           = true,
                ValidateAudience         = true,
                ValidateLifetime         = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer              = "https://example.com",
                ValidAudience            = "api",
                IssuerSigningKey         = signingKey,
            };

        // Create via SecurityTokenDescriptor
        public static string CreateAndWriteToken()
        {
            var key     = new SymmetricSecurityKey(new byte[32]);
            var creds   = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var handler = new JwtSecurityTokenHandler();

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer             = "https://example.com",
                Audience           = "api",
                Expires            = DateTime.UtcNow.AddHours(1),
                SigningCredentials  = creds,
            };

            var token = handler.CreateToken(descriptor);
            return handler.WriteToken(token);
        }

        // Create via CreateJwtSecurityToken overload
        public static string CreateJwtDirectly()
        {
            var key     = new SymmetricSecurityKey(new byte[32]);
            var creds   = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var handler = new JwtSecurityTokenHandler();

            var jwt = handler.CreateJwtSecurityToken(
                issuer:              "https://example.com",
                audience:            "api",
                subject:             new ClaimsIdentity(new[] { new Claim("sub", "user1") }),
                notBefore:           DateTime.UtcNow,
                expires:             DateTime.UtcNow.AddHours(1),
                issuedAt:            DateTime.UtcNow,
                signingCredentials:  creds);

            return handler.WriteToken(jwt);
        }

        // Create JWE (encrypted token)
        public static string CreateEncryptedToken()
        {
            using var rsa = RSA.Create(2048);
            var signingKey    = new SymmetricSecurityKey(new byte[32]);
            var encryptingKey = new RsaSecurityKey(rsa);

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.CreateJwtSecurityToken(
                issuer:                 "https://example.com",
                audience:               "api",
                subject:                new ClaimsIdentity(),
                notBefore:              DateTime.UtcNow,
                expires:                DateTime.UtcNow.AddHours(1),
                issuedAt:               DateTime.UtcNow,
                signingCredentials:     new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256),
                encryptingCredentials:  new EncryptingCredentials(encryptingKey,
                                            SecurityAlgorithms.RsaOAEP,
                                            SecurityAlgorithms.Aes256Gcm));
            return handler.WriteToken(jwt);
        }

        // Validate token (sync)
        public static ClaimsPrincipal ValidateToken(string token, SecurityKey key)
        {
            var handler = new JwtSecurityTokenHandler();
            return handler.ValidateToken(
                token,
                MakeValidationParams(key),
                out _);
        }

        // Validate token (async)
        public static Task<TokenValidationResult> ValidateTokenAsync(string token, SecurityKey key)
        {
            var handler = new JwtSecurityTokenHandler();
            return handler.ValidateTokenAsync(token, MakeValidationParams(key));
        }

        // Parse without validation (insecure — should be caught by CBOM)
        public static JwtSecurityToken ReadJwtUnsafe(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            return handler.ReadJwtToken(token);
        }

        public static bool CanRead(string token)
            => new JwtSecurityTokenHandler().CanReadToken(token);

        // Low-level crypto operations exposed on the classic handler
        public static string DecryptEncryptedToken(JwtSecurityToken token, SecurityKey key)
            => new JwtSecurityTokenHandler().DecryptToken(token, MakeValidationParams(key));

        public static bool ValidateTokenSignature(string token, SecurityKey key)
            => new JwtSecurityTokenHandler().ValidateSignature(token, MakeValidationParams(key));
    }

    // =========================================================================
    // JsonWebTokenHandler — newer async-first handler
    // (Microsoft.IdentityModel.JsonWebTokens)
    // Expected: jwt-create, jwt-validate, jwt-read
    // =========================================================================
    public static class JsonWebTokenHandlerTests
    {
        // Create via descriptor
        public static string CreateToken()
        {
            var key     = new SymmetricSecurityKey(new byte[32]);
            var creds   = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var handler = new JsonWebTokenHandler();

            return handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer            = "https://example.com",
                Audience          = "api",
                Expires           = DateTime.UtcNow.AddHours(1),
                SigningCredentials = creds,
            });
        }

        // Create async
        public static async Task<string> CreateTokenAsync()
        {
            var key     = new SymmetricSecurityKey(new byte[32]);
            var creds   = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
            var handler = new JsonWebTokenHandler();

            return await handler.CreateTokenAsync(new SecurityTokenDescriptor
            {
                Issuer            = "https://example.com",
                SigningCredentials = creds,
                Expires           = DateTime.UtcNow.AddHours(1),
            });
        }

        // Validate async (preferred API in JsonWebTokenHandler)
        public static async Task<TokenValidationResult> ValidateTokenAsync(string token, SecurityKey key)
        {
            var handler = new JsonWebTokenHandler();
            return await handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidateIssuer           = true,
                ValidIssuer              = "https://example.com",
                ValidateAudience         = true,
                ValidAudience            = "api",
                IssuerSigningKey         = key,
                ValidateIssuerSigningKey = true,
            });
        }

        // Parse without validation
        public static JsonWebToken ReadTokenUnsafe(string token)
            => new JsonWebTokenHandler().ReadJsonWebToken(token);
    }

    // =========================================================================
    // SecurityAlgorithms constant field reads — standalone references
    // Expected: hs256, hs384, hs512, rs256..rs512, ps256..ps512, es256..es512,
    //           a128kw, a256kw, rsa-oaep, rsa-oaep-256, rsa-pkcs1v15,
    //           a128cbc-hs256, a256cbc-hs512, a128gcm, a256gcm
    // =========================================================================
    public static class SecurityAlgorithmsTests
    {
        public static string GetHs256()          => SecurityAlgorithms.HmacSha256;
        public static string GetHs384()          => SecurityAlgorithms.HmacSha384;
        public static string GetHs512()          => SecurityAlgorithms.HmacSha512;
        public static string GetRs256()          => SecurityAlgorithms.RsaSha256;
        public static string GetRs384()          => SecurityAlgorithms.RsaSha384;
        public static string GetRs512()          => SecurityAlgorithms.RsaSha512;
        public static string GetPs256()          => SecurityAlgorithms.RsaSsaPssSha256;
        public static string GetPs384()          => SecurityAlgorithms.RsaSsaPssSha384;
        public static string GetPs512()          => SecurityAlgorithms.RsaSsaPssSha512;
        public static string GetEs256()          => SecurityAlgorithms.EcdsaSha256;
        public static string GetEs384()          => SecurityAlgorithms.EcdsaSha384;
        public static string GetEs512()          => SecurityAlgorithms.EcdsaSha512;
        public static string GetA128Kw()         => SecurityAlgorithms.Aes128KW;
        public static string GetA192Kw()         => SecurityAlgorithms.Aes192KW;
        public static string GetA256Kw()         => SecurityAlgorithms.Aes256KW;
        public static string GetRsaOaep()        => SecurityAlgorithms.RsaOAEP;
        public static string GetRsaOaep256()     => SecurityAlgorithms.RsaOAEP256;
        public static string GetRsaPkcs1()       => SecurityAlgorithms.RsaPKCS1;
        public static string GetA128CbcHs256()   => SecurityAlgorithms.Aes128CbcHmacSha256;
        public static string GetA192CbcHs384()   => SecurityAlgorithms.Aes192CbcHmacSha384;
        public static string GetA256CbcHs512()   => SecurityAlgorithms.Aes256CbcHmacSha512;
        public static string GetA128Gcm()        => SecurityAlgorithms.Aes128Gcm;
        public static string GetA192Gcm()        => SecurityAlgorithms.Aes192Gcm;
        public static string GetA256Gcm()        => SecurityAlgorithms.Aes256Gcm;
        public static string GetHmacSha256Sig()  => SecurityAlgorithms.HmacSha256Signature;
        public static string GetRsaSha256Sig()   => SecurityAlgorithms.RsaSha256Signature;
        public static string GetA128KeyWrap()    => SecurityAlgorithms.Aes128KeyWrap;
        public static string GetA256KeyWrap()    => SecurityAlgorithms.Aes256KeyWrap;
        public static string GetRsaSha384Sig()   => SecurityAlgorithms.RsaSha384Signature;
        public static string GetRsaSha512Sig()   => SecurityAlgorithms.RsaSha512Signature;
        public static string GetHmacSha384Sig()  => SecurityAlgorithms.HmacSha384Signature;
        public static string GetHmacSha512Sig()  => SecurityAlgorithms.HmacSha512Signature;
    }

    // =========================================================================
    // System.IdentityModel.Tokens.Jwt
    // Algorithm identifiers previously missing from the inventory
    // Expected algo tags: none, eddsa, ecdh-es, ecdh-es-a128kw, ecdh-es-a256kw,
    //                     sha256, sha384, sha512, es256, ps512, es256k
    // =========================================================================
    public static class JwtExtendedAlgorithmTests
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
    public static class JwtSignatureUriTests
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

}
