// Test suite for JoseJwt.ql
// Every method exercises at least one detection path in the QL query.
// The project is not intended to compile against the real jose-jwt package;
// type-stubs.cs provides declarations so the CodeQL extractor can resolve types.

using System.Collections.Generic;
using Jose;

namespace CbomTestSuite.Csharp
{
    // =========================================================================
    // JWT compact serialisation operations (JWT static class)
    // Expected: jose-jwt-encode, jose-jwt-decode, jose-jwt-verify,
    //           jose-jwt-decrypt, jose-jwt-inspect
    // =========================================================================
    public static class JoseJwtOperationTests
    {
        static readonly byte[] HmacKey = new byte[32];
        static object RsaKey  => null;
        static object EcKey   => null;

        // JWT.Encode — JWS (signed token)
        public static string SignHs256(object payload)
            => JWT.Encode(payload, HmacKey, JwsAlgorithm.HS256);

        // JWT.Encode — JWS (RS256)
        public static string SignRs256(object payload)
            => JWT.Encode(payload, RsaKey, JwsAlgorithm.RS256);

        // JWT.Encode — JWE (encrypted token)
        public static string EncryptRsaOaep256(object payload)
            => JWT.Encode(payload, RsaKey, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM);

        // JWT.EncodeBytes — binary payload
        public static string EncodeBytes(byte[] payload)
            => JWT.EncodeBytes(payload, HmacKey, JwsAlgorithm.HS256);

        // JWT.Decode
        public static string Decode(string token)
            => JWT.Decode(token, HmacKey);

        // JWT.DecodeBytes
        public static byte[] DecodeBytes(string token)
            => JWT.DecodeBytes(token, HmacKey);

        // JWT.DecodeToObject
        public static object DecodeToObject(string token)
            => JWT.DecodeToObject(token, HmacKey);

        // JWT.Verify (v5+)
        public static string Verify(string token)
            => JWT.Verify(token, RsaKey);

        // JWT.VerifyBytes (v5+)
        public static byte[] VerifyBytes(string token)
            => JWT.VerifyBytes(token, HmacKey);

        // JWT.Decrypt (v5+)
        public static string Decrypt(string token)
            => JWT.Decrypt(token, RsaKey);

        // JWT.DecryptBytes (v5+)
        public static byte[] DecryptBytes(string token)
            => JWT.DecryptBytes(token, HmacKey);

        // JWT.Payload — read payload without verification (insecure)
        public static string GetPayload(string token)
            => JWT.Payload(token);

        // JWT.PayloadBytes
        public static byte[] GetPayloadBytes(string token)
            => JWT.PayloadBytes(token);

        // JWT.Headers
        public static IDictionary<string, object> GetHeaders(string token)
            => JWT.Headers(token);

        // JWT.Signature
        public static string GetSignature(string token)
            => JWT.Signature(token);

        // JWT.SignatureBytes
        public static byte[] GetSignatureBytes(string token)
            => JWT.SignatureBytes(token);
    }

    // =========================================================================
    // JWE JSON serialisation operations (JWE static class)
    // Expected: jose-jwe-encrypt, jose-jwe-decrypt, jose-jwe-inspect
    // =========================================================================
    public static class JoseJweJsonTests
    {
        static readonly byte[] AesKey = new byte[32];
        static object RsaKey => null;

        public static string JweEncrypt(string payload)
            => JWE.Encrypt(payload, new[] { new JweRecipient(JweAlgorithm.A256KW, AesKey) }, JweEncryption.A256GCM);

        public static string JweEncryptBytes(byte[] payload)
            => JWE.EncryptBytes(payload, new[] { new JweRecipient(JweAlgorithm.RSA_OAEP_256, RsaKey) }, JweEncryption.A256GCM);

        public static JweToken JweDecrypt(string token)
            => JWE.Decrypt(token, AesKey);

        public static JweToken JweHeaders(string token)
            => JWE.Headers(token);
    }

    // =========================================================================
    // JwsAlgorithm enum field accesses
    // Expected: none, hs256, hs384, hs512, rs256, rs384, rs512,
    //           ps256, ps384, ps512, es256, es384, es512
    // Note: jose-jwt's JwsAlgorithm enum has no ES256K member (no secp256k1
    // support), unlike Microsoft.IdentityModel.Tokens.SecurityAlgorithms.
    // =========================================================================
    public static class JoseJwsAlgorithmTests
    {
        public static void AllJwsAlgorithms()
        {
            _ = JwsAlgorithm.none;
            _ = JwsAlgorithm.HS256;
            _ = JwsAlgorithm.HS384;
            _ = JwsAlgorithm.HS512;
            _ = JwsAlgorithm.RS256;
            _ = JwsAlgorithm.RS384;
            _ = JwsAlgorithm.RS512;
            _ = JwsAlgorithm.PS256;
            _ = JwsAlgorithm.PS384;
            _ = JwsAlgorithm.PS512;
            _ = JwsAlgorithm.ES256;
            _ = JwsAlgorithm.ES384;
            _ = JwsAlgorithm.ES512;
        }
    }

    // =========================================================================
    // JweAlgorithm enum field accesses (key management)
    // Expected: rsa-1_5, rsa-oaep, rsa-oaep-256, rsa-oaep-384, rsa-oaep-512,
    //   direct, aes-128-kw .. aes-256-gcm-kw, ecdh-es*, pbes2-*
    // =========================================================================
    public static class JoseJweAlgorithmTests
    {
        public static void AllJweAlgorithms()
        {
            _ = JweAlgorithm.RSA1_5;
            _ = JweAlgorithm.RSA_OAEP;
            _ = JweAlgorithm.RSA_OAEP_256;
            _ = JweAlgorithm.RSA_OAEP_384;
            _ = JweAlgorithm.RSA_OAEP_512;
            _ = JweAlgorithm.DIR;
            _ = JweAlgorithm.A128KW;
            _ = JweAlgorithm.A192KW;
            _ = JweAlgorithm.A256KW;
            _ = JweAlgorithm.A128GCMKW;
            _ = JweAlgorithm.A192GCMKW;
            _ = JweAlgorithm.A256GCMKW;
            _ = JweAlgorithm.ECDH_ES;
            _ = JweAlgorithm.ECDH_ES_A128KW;
            _ = JweAlgorithm.ECDH_ES_A192KW;
            _ = JweAlgorithm.ECDH_ES_A256KW;
            _ = JweAlgorithm.PBES2_HS256_A128KW;
            _ = JweAlgorithm.PBES2_HS384_A192KW;
            _ = JweAlgorithm.PBES2_HS512_A256KW;
        }
    }

    // =========================================================================
    // JweEncryption enum field accesses (content encryption)
    // Expected: aes-128-cbc-hs256, aes-192-cbc-hs384, aes-256-cbc-hs512,
    //           aes-128-gcm, aes-192-gcm, aes-256-gcm
    // =========================================================================
    public static class JoseJweEncryptionTests
    {
        public static void AllJweEncryptions()
        {
            _ = JweEncryption.A128CBC_HS256;
            _ = JweEncryption.A192CBC_HS384;
            _ = JweEncryption.A256CBC_HS512;
            _ = JweEncryption.A128GCM;
            _ = JweEncryption.A192GCM;
            _ = JweEncryption.A256GCM;
        }
    }

    // =========================================================================
    // JwtSettings — custom algorithm registration
    // Expected algo tags: jose-jwt-settings, jose-jwt-custom-algorithm
    // =========================================================================
    public static class JoseSettingsTests
    {
        public static JwtSettings CustomAlgorithms()
        {
            var settings = new JwtSettings();
            settings.RegisterJws(JwsAlgorithm.HS256, null);
            settings.RegisterJwa(JweAlgorithm.RSA_OAEP_256, null);
            settings.RegisterJwe(JweEncryption.A256GCM, null);
            settings.RegisterMapper(null);
            settings.RegisterJwsAlias("HS256Alias", JwsAlgorithm.HS256);
            settings.RegisterJweAlias("A256GCMAlias", JweEncryption.A256GCM);
            settings.RegisterJwaAlias("RSA-OAEP-256-Alias", JweAlgorithm.RSA_OAEP_256);
            settings.DeregisterJws(JwsAlgorithm.none);
            settings.DeregisterJwe(JweEncryption.A128GCM);
            settings.DeregisterJwa(JweAlgorithm.DIR);
            return settings;
        }
    }

    // =========================================================================
    // JWK / JWKS key material
    // Expected algo tags: jwk, jwks
    // =========================================================================
    public static class JoseJwkTests
    {
        public static Jwk FromRsa(System.Security.Cryptography.RSA key) => new Jwk(key, true);
        public static Jwk FromJson(string json)    => Jwk.FromJson(json);
        public static JwkSet SetFromJson(string j) => JwkSet.FromJson(j);
        public static JwkSet EmptySet()            => new JwkSet();
    }

    // =========================================================================
    // Generic call forms — the type argument is part of the resolved method name
    // Expected algo tags: jose-jwt-decode
    // =========================================================================
    public static class JoseGenericCallTests
    {
        public static System.Collections.Generic.IDictionary<string, object> DecodeGeneric(string token, byte[] key) =>
            JWT.Decode<System.Collections.Generic.IDictionary<string, object>>(token, key);

        public static Payload DecodeToTyped(string token, byte[] key) =>
            JWT.Decode<Payload>(token, key);

        public class Payload { public string Sub { get; set; } }
    }

}
