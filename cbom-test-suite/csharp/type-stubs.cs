// Minimal type declarations so the CodeQL C# extractor (--build-mode=none)
// can resolve ObjectCreation and MethodCall nodes without NuGet packages.
// These stubs are NOT meant to compile; they just give Roslyn enough
// information to produce a typed AST.
#pragma warning disable CS8603, CS8625, CS0626, CS0535, CS0649, CS0101

// =============================================================================
// Org.BouncyCastle.Crypto — core interfaces
// =============================================================================
namespace Org.BouncyCastle.Crypto
{
    public interface IDigest { }
    public interface IMac { }
    public interface IBlockCipher { }
    public interface IAeadBlockCipher { }
    public interface IAeadCipher { }
    public interface IStreamCipher { }
    public interface IBufferedCipher { }
    public interface ISigner { }
    public interface IAsymmetricBlockCipher { }
    public interface IAsymmetricCipherKeyPairGenerator { }
    public interface IBasicAgreement { }
    public interface IRawAgreement { }
    public interface IDerivationFunction { }
    public interface ICipherParameters { }
    public class PbeParametersGenerator { }
    public abstract class AsymmetricKeyParameter : ICipherParameters
    {
        protected AsymmetricKeyParameter(bool isPrivate) { }
        public bool IsPrivate { get; }
    }
}

// =============================================================================
// Org.BouncyCastle.Crypto.Digests
// =============================================================================
namespace Org.BouncyCastle.Crypto.Digests
{
    using Org.BouncyCastle.Crypto;

    public class Sha1Digest : IDigest { }
    public class Sha224Digest : IDigest { }
    public class Sha256Digest : IDigest { }
    public class Sha384Digest : IDigest { }
    public class Sha512Digest : IDigest { }
    public class MD2Digest : IDigest { }
    public class MD4Digest : IDigest { }
    public class MD5Digest : IDigest { }
    public class RipeMD128Digest : IDigest { }
    public class RipeMD160Digest : IDigest { }
    public class RipeMD256Digest : IDigest { }
    public class RipeMD320Digest : IDigest { }
    public class WhirlpoolDigest : IDigest { }
    public class TigerDigest : IDigest { }
    public class SM3Digest : IDigest { }
    public class GOST3411Digest : IDigest { }
    public class GOST3411_2012_256Digest : IDigest { }
    public class GOST3411_2012_512Digest : IDigest { }
    public class Blake2bDigest : IDigest { public Blake2bDigest(int digestSize) { } }
    public class Blake2sDigest : IDigest { public Blake2sDigest(int digestSize) { } }
    public class Blake3Digest : IDigest { }
    public class NullDigest : IDigest { }
    public class Sha3Digest : IDigest { public Sha3Digest(int bitLength) { } }
    public class KeccakDigest : IDigest { public KeccakDigest(int bitLength) { } }
    public class ShakeDigest : IDigest { public ShakeDigest(int bitLength) { } }
    public class CShakeDigest : IDigest { public CShakeDigest(int bitLength, byte[] n, byte[] s) { } }
    public class SkeinDigest : IDigest { public SkeinDigest(int stateSize, int outputSize) { } }
}

// =============================================================================
// Org.BouncyCastle.Crypto.Macs
// =============================================================================
namespace Org.BouncyCastle.Crypto.Macs
{
    using Org.BouncyCastle.Crypto;

    public class HMac : IMac { public HMac(IDigest digest) { } }
    public class CMac : IMac { public CMac(IBlockCipher cipher) { } }
    public class Poly1305 : IMac { public Poly1305(IBlockCipher cipher) { } }
    public class GMac : IMac { public GMac(IAeadBlockCipher cipher) { } }
    public class CBCBlockCipherMac : IMac { public CBCBlockCipherMac(IBlockCipher cipher) { } }
    public class CFBBlockCipherMac : IMac { public CFBBlockCipherMac(IBlockCipher cipher, int cfbBits) { } }
    public class ISO9797Alg3Mac : IMac { public ISO9797Alg3Mac(IBlockCipher cipher) { } }
    public class SipHash : IMac { }
}

// =============================================================================
// Org.BouncyCastle.Crypto.Engines
// =============================================================================
namespace Org.BouncyCastle.Crypto.Engines
{
    using Org.BouncyCastle.Crypto;

    public class AesEngine : IBlockCipher { }
    public class AesLightEngine : IBlockCipher { }
    public class DesEngine : IBlockCipher { }
    public class DesEdeEngine : IBlockCipher { }
    public class BlowfishEngine : IBlockCipher { }
    public class TwofishEngine : IBlockCipher { }
    public class CamelliaEngine : IBlockCipher { }
    public class CamelliaLightEngine : IBlockCipher { }
    public class Rc2Engine : IBlockCipher { }
    public class Rc6Engine : IBlockCipher { }
    public class Cast5Engine : IBlockCipher { }
    public class Cast6Engine : IBlockCipher { }
    public class SerpentEngine : IBlockCipher { }
    public class SerpentLightEngine : IBlockCipher { }
    public class SkipjackEngine : IBlockCipher { }
    public class TeaEngine : IBlockCipher { }
    public class XteaEngine : IBlockCipher { }
    public class SM4Engine : IBlockCipher { }
    public class AriaEngine : IBlockCipher { }
    public class Gost28147Engine : IBlockCipher { }
    public class IdeaEngine : IBlockCipher { }
    public class SeedEngine : IBlockCipher { }
    public class NoekeonEngine : IBlockCipher { }
    public class ThreefishEngine : IBlockCipher { public ThreefishEngine(int blockSize) { } }
    public class NullEngine : IBlockCipher { }

    public class RsaEngine : IAsymmetricBlockCipher { }
    public class RsaBlindedEngine : IAsymmetricBlockCipher { }
    public class ElGamalEngine : IAsymmetricBlockCipher { }
    public class SM2Engine : IAsymmetricBlockCipher { }

    // Stream ciphers
    public class ChaCha7539Engine : IStreamCipher { }
    public class ChaChaEngine : IStreamCipher { }
    public class Salsa20Engine : IStreamCipher { }
    public class XSalsa20Engine : IStreamCipher { }
    public class HC128Engine : IStreamCipher { }
    public class HC256Engine : IStreamCipher { }
    public class Snow3GEngine : IStreamCipher { }
    public class VmpcEngine : IStreamCipher { }
    public class VmpcKsaEngine : IStreamCipher { }
    public class Grain128Engine : IStreamCipher { }
    public class Grain128AEADEngine : IAeadCipher { }
    public class RC4Engine : IStreamCipher { }
    public class ZucEngine : IStreamCipher { }
    public class IsaacEngine : IStreamCipher { }
}

// =============================================================================
// Org.BouncyCastle.Crypto.Modes
// =============================================================================
namespace Org.BouncyCastle.Crypto.Modes
{
    using Org.BouncyCastle.Crypto;

    public class GcmBlockCipher : IAeadBlockCipher { public GcmBlockCipher(IBlockCipher cipher) { } }
    public class CcmBlockCipher : IAeadBlockCipher { public CcmBlockCipher(IBlockCipher cipher) { } }
    public class EaxBlockCipher : IAeadBlockCipher { public EaxBlockCipher(IBlockCipher cipher) { } }
    public class OcbBlockCipher : IAeadBlockCipher { public OcbBlockCipher(IBlockCipher hashCipher, IBlockCipher mainCipher) { } }
    public class CbcBlockCipher : IBlockCipher { public CbcBlockCipher(IBlockCipher cipher) { } }
    public class CfbBlockCipher : IBlockCipher { public CfbBlockCipher(IBlockCipher cipher, int bitBlockSize) { } }
    public class OfbBlockCipher : IBlockCipher { public OfbBlockCipher(IBlockCipher cipher, int blockSize) { } }
    public class SicBlockCipher : IBlockCipher { public SicBlockCipher(IBlockCipher cipher) { } }
    public class GofbBlockCipher : IBlockCipher { public GofbBlockCipher(IBlockCipher cipher) { } }
    public class CtsBlockCipher : IBlockCipher { public CtsBlockCipher(IBlockCipher cipher) { } }
    public class ChaCha20Poly1305 : IAeadCipher { }
}

// =============================================================================
// Org.BouncyCastle.Crypto.Encodings
// =============================================================================
namespace Org.BouncyCastle.Crypto.Encodings
{
    using Org.BouncyCastle.Crypto;

    public class OaepEncoding : IAsymmetricBlockCipher
    {
        public OaepEncoding(IAsymmetricBlockCipher engine, IDigest hash) { }
        public OaepEncoding(IAsymmetricBlockCipher engine, IDigest hash, IDigest mgfHash, byte[] encodingParams) { }
    }
    public class Pkcs1Encoding : IAsymmetricBlockCipher { public Pkcs1Encoding(IAsymmetricBlockCipher engine) { } }
    public class Iso9796d1Encoding : IAsymmetricBlockCipher { public Iso9796d1Encoding(IAsymmetricBlockCipher engine) { } }
}

// =============================================================================
// Org.BouncyCastle.Crypto.Signers
// =============================================================================
namespace Org.BouncyCastle.Crypto.Signers
{
    using Org.BouncyCastle.Crypto;

    public class PssSigner : ISigner { public PssSigner(IAsymmetricBlockCipher engine, IDigest digest) { } }
    public class Iso9796d2Signer : ISigner { public Iso9796d2Signer(IAsymmetricBlockCipher engine, IDigest digest) { } }
    public class X931Signer : ISigner { public X931Signer(IAsymmetricBlockCipher engine, IDigest digest) { } }
    public class ECDsaSigner : ISigner { }
    public class ECNRSigner : ISigner { }
    public class ECGOST3410Signer : ISigner { }
    public class SM2Signer : ISigner { }
    public class Ed25519Signer : ISigner { }
    public class Ed25519ctxSigner : ISigner { }
    public class Ed25519phSigner : ISigner { }
    public class Ed448Signer : ISigner { }
    public class Ed448phSigner : ISigner { }
    public class DsaSigner : ISigner { }
    public class GOST3410Signer : ISigner { }
}

// =============================================================================
// Org.BouncyCastle.Crypto.Agreement
// =============================================================================
namespace Org.BouncyCastle.Crypto.Agreement
{
    using Org.BouncyCastle.Crypto;

    public class ECDHBasicAgreement : IBasicAgreement { }
    public class ECDHCBasicAgreement : IBasicAgreement { }
    public class ECMqvBasicAgreement : IBasicAgreement { }
    public class SM2Agreement : IBasicAgreement { }
    public class X25519Agreement : IRawAgreement { }
    public class X448Agreement : IRawAgreement { }
}

// =============================================================================
// Org.BouncyCastle.Crypto.Generators
// =============================================================================
namespace Org.BouncyCastle.Crypto.Generators
{
    using Org.BouncyCastle.Crypto;

    public class RsaKeyPairGenerator : IAsymmetricCipherKeyPairGenerator { }
    public class ECKeyPairGenerator : IAsymmetricCipherKeyPairGenerator { }
    public class DsaKeyPairGenerator : IAsymmetricCipherKeyPairGenerator { }
    public class ElGamalKeyPairGenerator : IAsymmetricCipherKeyPairGenerator { }
    public class Ed25519KeyPairGenerator : IAsymmetricCipherKeyPairGenerator { }
    public class Ed448KeyPairGenerator : IAsymmetricCipherKeyPairGenerator { }
    public class X25519KeyPairGenerator : IAsymmetricCipherKeyPairGenerator { }
    public class X448KeyPairGenerator : IAsymmetricCipherKeyPairGenerator { }

    public class Pkcs5S1ParametersGenerator : PbeParametersGenerator { public Pkcs5S1ParametersGenerator(IDigest digest) { } }
    public class Pkcs5S2ParametersGenerator : PbeParametersGenerator { public Pkcs5S2ParametersGenerator(IDigest digest) { } }
    public class HkdfBytesGenerator : IDerivationFunction { public HkdfBytesGenerator(IDigest digest) { } }
    public class MGF1BytesGenerator : IDerivationFunction { public MGF1BytesGenerator(IDigest digest) { } }
    public class ConcatenationKdfGenerator : IDerivationFunction { public ConcatenationKdfGenerator(IDigest digest) { } }
    public class KdfCounterBytesGenerator { public KdfCounterBytesGenerator(IMac mac) { } }
    public class Argon2BytesGenerator { }
    public class SCrypt { public static byte[] Generate(byte[] p, byte[] s, int n, int r, int pParam, int dkLen) => null; }
    public class BCrypt { public static byte[] Generate(byte[] p, byte[] s, int cost) => null; }
    public class DigestRandomGenerator { public DigestRandomGenerator(IDigest digest) { } }
    public class VmpcRandomGenerator { }
    public class SP800SecureRandomBuilder { }
}

// =============================================================================
// Org.BouncyCastle.Security
// =============================================================================
namespace Org.BouncyCastle.Security
{
    using Org.BouncyCastle.Crypto;

    public class SecureRandom
    {
        public SecureRandom() { }
        public static SecureRandom GetInstance(string algorithm) => null;
    }
    public class DigestUtilities { public static IDigest GetDigest(string algorithm) => null; }
    public class MacUtilities { public static IMac GetMac(string algorithm) => null; }
    public class GeneratorUtilities { public static object GetKeyGenerator(string algorithm) => null; }
    public class CipherUtilities { public static IBufferedCipher GetCipher(string algorithm) => null; }
    public class SignerUtilities { public static ISigner GetSigner(string algorithm) => null; }
    public class KeyPairGeneratorUtilities { public static IAsymmetricCipherKeyPairGenerator GetKeyPairGenerator(string algorithm) => null; }
    public class AgreementUtilities { public static IBasicAgreement GetBasicAgreement(string algorithm) => null; }
}

// =============================================================================
// Org.BouncyCastle.X509
// =============================================================================
namespace Org.BouncyCastle.X509
{
    public class X509V1CertificateGenerator { }
    public class X509V3CertificateGenerator { }
    public class X509V2CrlGenerator { }
    public class X509CertificateParser { }
    public class PkixCertPathBuilder { }
    public class PkixCertPathValidator { }
}

// =============================================================================
// Org.BouncyCastle.Pkcs
// =============================================================================
namespace Org.BouncyCastle.Pkcs
{
    public class Pkcs12Store { }
    public class Pkcs10CertificationRequest { }
    public class Pkcs8Generator { public Pkcs8Generator(object key, object encryptor) { } }
}

// =============================================================================
// Org.BouncyCastle.OpenSsl
// =============================================================================
namespace Org.BouncyCastle.OpenSsl
{
    public class PemReader { public PemReader(System.IO.TextReader reader) { } }
    public class PemWriter { public PemWriter(System.IO.TextWriter writer) { } }
}

// =============================================================================
// Microsoft.AspNetCore.DataProtection
// =============================================================================
namespace Microsoft.AspNetCore.DataProtection
{
    public interface IDataProtectionProvider
    {
        IDataProtector CreateProtector(string purpose);
    }
    public interface IDataProtector : IDataProtectionProvider
    {
        byte[] Protect(byte[] plaintext);
        byte[] Unprotect(byte[] protectedData);
        ITimeLimitedDataProtector ToTimeLimitedDataProtector();
    }
    public interface ITimeLimitedDataProtector
    {
        byte[] Protect(byte[] plaintext, System.DateTimeOffset expiration);
        byte[] Unprotect(byte[] protectedData, out System.DateTimeOffset expiration);
    }
    public static class DataProtectionCommonExtensions
    {
        public static string Protect(IDataProtector protector, string plaintext) => null;
        public static string Unprotect(IDataProtector protector, string protectedData) => null;
        public static IDataProtector CreateProtector(IDataProtectionProvider provider, params string[] purposes) => null;
    }
    public class DataProtectionProvider : IDataProtectionProvider
    {
        public DataProtectionProvider(System.IO.DirectoryInfo keyDir) { }
        public IDataProtector CreateProtector(string purpose) => null;
    }
    public class EphemeralDataProtectionProvider : IDataProtectionProvider
    {
        public IDataProtector CreateProtector(string purpose) => null;
    }
    public interface IDataProtectionBuilder
    {
        IDataProtectionBuilder SetApplicationName(string name);
        IDataProtectionBuilder SetDefaultKeyLifetime(System.TimeSpan lifetime);
        IDataProtectionBuilder PersistKeysToFileSystem(System.IO.DirectoryInfo dir);
        IDataProtectionBuilder ProtectKeysWithCertificate(System.Security.Cryptography.X509Certificates.X509Certificate2 cert);
        IDataProtectionBuilder DisableAutomaticKeyGeneration();
        IDataProtectionBuilder ProtectKeysWithDpapi(bool protectToLocalMachine = false);
        IDataProtectionBuilder ProtectKeysWithDpapiNG();
        IDataProtectionBuilder UseEphemeralDataProtectionProvider();
        IDataProtectionBuilder PersistKeysToAzureBlobStorage(System.Uri blobUri);
        IDataProtectionBuilder ProtectKeysWithAzureKeyVault(System.Uri keyUri, object tokenCredential);
        IDataProtectionBuilder UseCryptographicAlgorithms(
            AuthenticatedEncryption.AuthenticatedEncryptorConfiguration configuration);
        IDataProtectionBuilder UseCustomCryptographicAlgorithms(
            AuthenticatedEncryption.ManagedAuthenticatedEncryptorConfiguration configuration);
        IDataProtectionBuilder UseCustomCryptographicAlgorithms(
            AuthenticatedEncryption.CngCbcAuthenticatedEncryptorConfiguration configuration);
        IDataProtectionBuilder UseCustomCryptographicAlgorithms(
            AuthenticatedEncryption.CngGcmAuthenticatedEncryptorConfiguration configuration);
    }
}

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption
{
    public class AuthenticatedEncryptorConfiguration
    {
        public EncryptionAlgorithm EncryptionAlgorithm { get; set; }
        public ValidationAlgorithm ValidationAlgorithm { get; set; }
    }
    public enum EncryptionAlgorithm
    {
        AES_128_CBC, AES_192_CBC, AES_256_CBC,
        AES_128_GCM, AES_192_GCM, AES_256_GCM
    }
    public enum ValidationAlgorithm { HMACSHA256, HMACSHA512 }
    public class ManagedAuthenticatedEncryptorConfiguration
    {
        public System.Type EncryptionAlgorithmType { get; set; }
        public int EncryptionAlgorithmKeySize { get; set; }
        public System.Type ValidationAlgorithmType { get; set; }
    }
    public class CngCbcAuthenticatedEncryptorConfiguration
    {
        public string EncryptionAlgorithm { get; set; }
        public int EncryptionAlgorithmKeySize { get; set; }
        public string HashAlgorithm { get; set; }
    }
    public class CngGcmAuthenticatedEncryptorConfiguration
    {
        public string EncryptionAlgorithm { get; set; }
        public int EncryptionAlgorithmKeySize { get; set; }
    }
    public interface IAuthenticatedEncryptor
    {
        byte[] Encrypt(System.ArraySegment<byte> plaintext, System.ArraySegment<byte> aad);
        byte[] Decrypt(System.ArraySegment<byte> ciphertext, System.ArraySegment<byte> aad);
    }
}

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel { }

namespace Microsoft.AspNetCore.DataProtection.KeyManagement
{
    public interface IKeyManager
    {
        object CreateNewKey(System.DateTimeOffset activationDate, System.DateTimeOffset expirationDate);
        System.Collections.Generic.IReadOnlyCollection<object> GetAllKeys();
        void RevokeKey(System.Guid keyId, string reason = null);
        void RevokeAllKeys(System.DateTimeOffset revocationDate, string reason = null);
    }
    public class KeyManagementOptions { }
    public class XmlKeyManager : IKeyManager
    {
        public XmlKeyManager(object options, object activator, object loggerFactory) { }
        public object CreateNewKey(System.DateTimeOffset a, System.DateTimeOffset e) => null;
        public System.Collections.Generic.IReadOnlyCollection<object> GetAllKeys() => null;
        public void RevokeKey(System.Guid keyId, string reason = null) { }
        public void RevokeAllKeys(System.DateTimeOffset revocationDate, string reason = null) { }
    }
}

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
    public class CertificateXmlEncryptor
    {
        public CertificateXmlEncryptor(System.Security.Cryptography.X509Certificates.X509Certificate2 cert, System.IServiceProvider services) { }
    }
    public class DpapiXmlEncryptor
    {
        public DpapiXmlEncryptor(bool protectToLocalMachine, System.IServiceProvider services) { }
    }
    public class DpapiNGXmlEncryptor
    {
        public DpapiNGXmlEncryptor(string protectionDescriptorRule, DpapiNGProtectionDescriptorFlags flags, System.IServiceProvider services) { }
    }
    public enum DpapiNGProtectionDescriptorFlags { None }
    public interface IXmlEncryptor { object Encrypt(object plaintextElement); }
    public interface IXmlDecryptor { object Decrypt(object encryptedElement); }
}

namespace Microsoft.AspNetCore.DataProtection.Internal
{
    public class IActivator { public static readonly IActivator Instance = new IActivator(); }
}

// =============================================================================
// Microsoft.Extensions stubs (DI, Options, Logging)
// =============================================================================
namespace Microsoft.Extensions.DependencyInjection
{
    public interface IServiceCollection { }

    // Concrete collection needed so BuildServiceProvider() return type is known.
    public class ServiceCollection : IServiceCollection { }

    public static class ServiceCollectionExtensions
    {
        public static ServiceProvider BuildServiceProvider(this IServiceCollection services) => null;
    }

    // GetRequiredService<T> must be generic so Roslyn infers the concrete return type.
    public static class ServiceProviderServiceExtensions
    {
        public static T GetRequiredService<T>(this System.IServiceProvider sp) => default(T);
        public static T GetService<T>(this System.IServiceProvider sp) => default(T);
    }

    public static class DataProtectionServiceCollectionExtensions
    {
        public static Microsoft.AspNetCore.DataProtection.IDataProtectionBuilder AddDataProtection(this IServiceCollection services) => null;
    }
}

// ServiceProvider must implement System.IServiceProvider so GetRequiredService<T> extension resolves.
namespace Microsoft.Extensions.DependencyInjection
{
    public class ServiceProvider : System.IDisposable, System.IServiceProvider
    {
        public object GetService(System.Type serviceType) => null;
        public void Dispose() { }
    }
}

namespace Microsoft.Extensions.Options
{
    public static class Options
    {
        public static object Create<T>(T value) => null;
    }
}

namespace Microsoft.Extensions.Logging.Abstractions
{
    public class NullLoggerFactory
    {
        public static readonly NullLoggerFactory Instance = new NullLoggerFactory();
    }
}

// =============================================================================
// Azure.Core stubs (minimal — credential and response types only)
// =============================================================================
namespace Azure
{
    public class Response<T> { public T Value { get; } }
    public class Operation<T>
    {
        public T Value { get; }
        public System.Threading.Tasks.Task<Response<T>> WaitForCompletionAsync() => null;
    }
}

namespace Azure.Core
{
    public abstract class TokenCredential { }
}

// =============================================================================
// Azure.Security.KeyVault.Keys stubs
// =============================================================================
namespace Azure.Security.KeyVault.Keys
{
    public class KeyClient
    {
        public KeyClient(System.Uri vaultUri, Azure.Core.TokenCredential credential) { }
        public Azure.Response<KeyVaultKey>          CreateKey(string name, KeyType keyType) => null;
        public Azure.Response<KeyVaultKey>          CreateRsaKey(CreateRsaKeyOptions options) => null;
        public Azure.Response<KeyVaultKey>          CreateEcKey(CreateEcKeyOptions options) => null;
        public Azure.Response<KeyVaultKey>          CreateOctKey(CreateOctKeyOptions options) => null;
        public Azure.Response<KeyVaultKey>          ImportKey(ImportKeyOptions options) => null;
        public Azure.Response<KeyVaultKey>          RotateKey(string name) => null;
        public Azure.Response<KeyVaultKey>          GetKey(string name) => null;
        public DeleteKeyOperation                   DeleteKey(string name) => null;
        public Azure.Response<KeyProperties>        UpdateKeyProperties(KeyProperties properties) => null;
        public Azure.Response<byte[]>               BackupKey(string name) => null;
        public Azure.Response<KeyVaultKey>          RestoreKeyBackup(byte[] backup) => null;
        public RecoverDeletedKeyOperation           RecoverDeletedKey(string name) => null;
        public void                                 PurgeDeletedKey(string name) { }
        public Azure.Response<KeyRotationPolicy>    GetKeyRotationPolicy(string name) => null;
        public Azure.Response<KeyRotationPolicy>    UpdateKeyRotationPolicy(string name, KeyRotationPolicy policy) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultKey>>          GetKeyAsync(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultKey>>          CreateKeyAsync(string name, KeyType keyType) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultKey>>          CreateRsaKeyAsync(CreateRsaKeyOptions options) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultKey>>          CreateEcKeyAsync(CreateEcKeyOptions options) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultKey>>          CreateOctKeyAsync(CreateOctKeyOptions options) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultKey>>          ImportKeyAsync(ImportKeyOptions options) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultKey>>          RotateKeyAsync(string name) => null;
        public System.Threading.Tasks.Task<DeleteKeyOperation>                   DeleteKeyAsync(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyProperties>>        UpdateKeyPropertiesAsync(KeyProperties properties) => null;
        public System.Threading.Tasks.Task<Azure.Response<byte[]>>               BackupKeyAsync(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultKey>>          RestoreKeyBackupAsync(byte[] backup) => null;
        public System.Threading.Tasks.Task<RecoverDeletedKeyOperation>           RecoverDeletedKeyAsync(string name) => null;
        public System.Threading.Tasks.Task                                       PurgeDeletedKeyAsync(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyRotationPolicy>>    GetKeyRotationPolicyAsync(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyRotationPolicy>>    UpdateKeyRotationPolicyAsync(string name, KeyRotationPolicy policy) => null;
        public Azure.Response<byte[]>                                            GetRandomBytes(int count) => null;
        public System.Threading.Tasks.Task<Azure.Response<byte[]>>               GetRandomBytesAsync(int count) => null;
        public Azure.Response<byte[]>                                            ReleaseKey(string name, string target) => null;
        public System.Threading.Tasks.Task<Azure.Response<byte[]>>               ReleaseKeyAsync(string name, string target) => null;
    }

    public class KeyVaultKey    { public KeyProperties Properties { get; } public System.Uri Id { get; } public string Name { get; } }
    public class KeyProperties  { public string Version { get; } }
    public class KeyRotationPolicy { }
    public class DeleteKeyOperation          : Azure.Operation<DeletedKey> { }
    public class DeletedKey { }
    public class RecoverDeletedKeyOperation  : Azure.Operation<KeyVaultKey> { }

    public struct KeyType
    {
        public static readonly KeyType Rsa    = default;
        public static readonly KeyType RsaHsm = default;
        public static readonly KeyType Ec     = default;
        public static readonly KeyType EcHsm  = default;
        public static readonly KeyType Oct    = default;
        public static readonly KeyType OctHsm = default;
    }

    public class CreateRsaKeyOptions { public CreateRsaKeyOptions(string name) { } public int? KeySize { get; set; } }
    public class CreateEcKeyOptions  { public CreateEcKeyOptions(string name) { } }
    public class CreateOctKeyOptions { public CreateOctKeyOptions(string name) { } public int? KeySize { get; set; } }
    public class ImportKeyOptions    { public ImportKeyOptions(string name, JsonWebKey key) { } }
    public class JsonWebKey { }
}

// =============================================================================
// Azure.Security.KeyVault.Keys.Cryptography stubs
// =============================================================================
namespace Azure.Security.KeyVault.Keys.Cryptography
{
    public class CryptographyClient
    {
        public CryptographyClient(System.Uri keyId, Azure.Core.TokenCredential credential) { }
        public EncryptResult  Encrypt(EncryptionAlgorithm algorithm, byte[] plaintext) => null;
        public DecryptResult  Decrypt(EncryptionAlgorithm algorithm, byte[] ciphertext) => null;
        public SignResult     Sign(SignatureAlgorithm algorithm, byte[] digest) => null;
        public SignResult     SignData(SignatureAlgorithm algorithm, byte[] data) => null;
        public VerifyResult   Verify(SignatureAlgorithm algorithm, byte[] digest, byte[] signature) => null;
        public VerifyResult   VerifyData(SignatureAlgorithm algorithm, byte[] data, byte[] signature) => null;
        public WrapResult     WrapKey(KeyWrapAlgorithm algorithm, byte[] key) => null;
        public UnwrapResult   UnwrapKey(KeyWrapAlgorithm algorithm, byte[] encryptedKey) => null;
        public System.Threading.Tasks.Task<EncryptResult>  EncryptAsync(EncryptionAlgorithm algorithm, byte[] plaintext) => null;
        public System.Threading.Tasks.Task<DecryptResult>  DecryptAsync(EncryptionAlgorithm algorithm, byte[] ciphertext) => null;
        public System.Threading.Tasks.Task<SignResult>     SignAsync(SignatureAlgorithm algorithm, byte[] digest) => null;
        public System.Threading.Tasks.Task<SignResult>     SignDataAsync(SignatureAlgorithm algorithm, byte[] data) => null;
        public System.Threading.Tasks.Task<VerifyResult>   VerifyAsync(SignatureAlgorithm algorithm, byte[] digest, byte[] signature) => null;
        public System.Threading.Tasks.Task<VerifyResult>   VerifyDataAsync(SignatureAlgorithm algorithm, byte[] data, byte[] signature) => null;
        public System.Threading.Tasks.Task<WrapResult>     WrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] key) => null;
        public System.Threading.Tasks.Task<UnwrapResult>   UnwrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] encryptedKey) => null;
    }

    public struct EncryptionAlgorithm
    {
        public static readonly EncryptionAlgorithm Rsa15      = default;
        public static readonly EncryptionAlgorithm RsaOaep    = default;
        public static readonly EncryptionAlgorithm RsaOaep256 = default;
        public static readonly EncryptionAlgorithm A128Gcm    = default;
        public static readonly EncryptionAlgorithm A192Gcm    = default;
        public static readonly EncryptionAlgorithm A256Gcm    = default;
        public static readonly EncryptionAlgorithm A128CbcPad = default;
        public static readonly EncryptionAlgorithm A192CbcPad = default;
        public static readonly EncryptionAlgorithm A256CbcPad = default;
        public static readonly EncryptionAlgorithm A128Cbc    = default;
        public static readonly EncryptionAlgorithm A192Cbc    = default;
        public static readonly EncryptionAlgorithm A256Cbc    = default;
    }

    public struct SignatureAlgorithm
    {
        public static readonly SignatureAlgorithm RS256  = default;
        public static readonly SignatureAlgorithm RS384  = default;
        public static readonly SignatureAlgorithm RS512  = default;
        public static readonly SignatureAlgorithm PS256  = default;
        public static readonly SignatureAlgorithm PS384  = default;
        public static readonly SignatureAlgorithm PS512  = default;
        public static readonly SignatureAlgorithm ES256  = default;
        public static readonly SignatureAlgorithm ES384  = default;
        public static readonly SignatureAlgorithm ES512  = default;
        public static readonly SignatureAlgorithm ES256K = default;
    }

    public struct KeyWrapAlgorithm
    {
        public static readonly KeyWrapAlgorithm Rsa15      = default;
        public static readonly KeyWrapAlgorithm RsaOaep    = default;
        public static readonly KeyWrapAlgorithm RsaOaep256 = default;
        public static readonly KeyWrapAlgorithm A128KW     = default;
        public static readonly KeyWrapAlgorithm A192KW     = default;
        public static readonly KeyWrapAlgorithm A256KW     = default;
    }

    public class EncryptResult  { }
    public class DecryptResult  { }
    public class SignResult     { }
    public class VerifyResult   { }
    public class WrapResult     { }
    public class UnwrapResult   { }
}

// =============================================================================
// Azure.Security.KeyVault.Secrets stubs
// =============================================================================
namespace Azure.Security.KeyVault.Secrets
{
    public class SecretClient
    {
        public SecretClient(System.Uri vaultUri, Azure.Core.TokenCredential credential) { }
        public Azure.Response<KeyVaultSecret> GetSecret(string name) => null;
        public Azure.Response<KeyVaultSecret> SetSecret(string name, string value) => null;
        public DeleteSecretOperation          DeleteSecret(string name) => null;
        public Azure.Response<SecretProperties>       UpdateSecretProperties(SecretProperties properties) => null;
        public Azure.Response<byte[]>                  BackupSecret(string name) => null;
        public Azure.Response<KeyVaultSecret>          RestoreSecretBackup(byte[] backup) => null;
        public RecoverDeletedSecretOperation           RecoverDeletedSecret(string name) => null;
        public void                                    PurgeDeletedSecret(string name) { }
        public Azure.Response<DeletedSecret>           GetDeletedSecret(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultSecret>>   GetSecretAsync(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultSecret>>   SetSecretAsync(string name, string value) => null;
        public System.Threading.Tasks.Task<DeleteSecretOperation>            StartDeleteSecretAsync(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultSecret>>   UpdateSecretPropertiesAsync(SecretProperties properties) => null;
        public System.Threading.Tasks.Task<Azure.Response<byte[]>>           BackupSecretAsync(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultSecret>>   RestoreSecretBackupAsync(byte[] backup) => null;
        public System.Threading.Tasks.Task<RecoverDeletedSecretOperation>    RecoverDeletedSecretAsync(string name) => null;
        public System.Threading.Tasks.Task                                   PurgeDeletedSecretAsync(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<DeletedSecret>>    GetDeletedSecretAsync(string name) => null;
    }

    public class RecoverDeletedSecretOperation : Azure.Operation<KeyVaultSecret> { }

    public class KeyVaultSecret { public string Name { get; } public string Value { get; } public SecretProperties Properties { get; } }
    public class SecretProperties { public System.DateTimeOffset? ExpiresOn { get; set; } public string Version { get; } }
    public class DeleteSecretOperation : Azure.Operation<DeletedSecret> { }
    public class DeletedSecret { public string Name { get; } }
}

// =============================================================================
// Azure.Security.KeyVault.Certificates stubs
// =============================================================================
namespace Azure.Security.KeyVault.Certificates
{
    public class CertificateClient
    {
        public CertificateClient(System.Uri vaultUri, Azure.Core.TokenCredential credential) { }
        public CertificateOperation                       StartCreateCertificate(string name, CertificatePolicy policy) => null;
        public Azure.Response<KeyVaultCertificateWithPolicy> GetCertificate(string name) => null;
        public Azure.Response<KeyVaultCertificateWithPolicy> ImportCertificate(ImportCertificateOptions options) => null;
        public Azure.Response<KeyVaultCertificateWithPolicy> MergeCertificate(MergeCertificateOptions options) => null;
        public Azure.Response<CertificatePolicy>             GetCertificatePolicy(string name) => null;
        public Azure.Response<CertificatePolicy>             UpdateCertificatePolicy(string name, CertificatePolicy policy) => null;
        public Azure.Response<byte[]>                        BackupCertificate(string name) => null;
        public Azure.Response<KeyVaultCertificateWithPolicy> RestoreCertificateBackup(byte[] backup) => null;
        public DeleteCertificateOperation                    StartDeleteCertificate(string name) => null;
        public RecoverDeletedCertificateOperation            StartRecoverDeletedCertificate(string name) => null;
        public void                                          PurgeDeletedCertificate(string name) { }
        public CertificateOperation                          GetCertificateOperation(string name) => null;
        public CertificateOperation                          CancelCertificateOperation(string name) => null;
        public System.Threading.Tasks.Task<CertificateOperation>                          StartCreateCertificateAsync(string name, CertificatePolicy policy) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultCertificateWithPolicy>> GetCertificateAsync(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultCertificateWithPolicy>> ImportCertificateAsync(ImportCertificateOptions options) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultCertificateWithPolicy>> MergeCertificateAsync(MergeCertificateOptions options) => null;
        public System.Threading.Tasks.Task<Azure.Response<CertificatePolicy>>             GetCertificatePolicyAsync(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<CertificatePolicy>>             UpdateCertificatePolicyAsync(string name, CertificatePolicy policy) => null;
        public System.Threading.Tasks.Task<Azure.Response<byte[]>>                        BackupCertificateAsync(string name) => null;
        public System.Threading.Tasks.Task<Azure.Response<KeyVaultCertificateWithPolicy>> RestoreCertificateBackupAsync(byte[] backup) => null;
        public System.Threading.Tasks.Task<DeleteCertificateOperation>                    StartDeleteCertificateAsync(string name) => null;
        public System.Threading.Tasks.Task<RecoverDeletedCertificateOperation>            StartRecoverDeletedCertificateAsync(string name) => null;
        public System.Threading.Tasks.Task                                                PurgeDeletedCertificateAsync(string name) => null;
        public System.Threading.Tasks.Task<CertificateOperation>                          GetCertificateOperationAsync(string name) => null;
        public System.Threading.Tasks.Task<CertificateOperation>                          CancelCertificateOperationAsync(string name) => null;
    }

    public class CertificatePolicy
    {
        public static readonly CertificatePolicy Default = null;
        public CertificatePolicy(string issuerName, string subject) { }
        public int? KeySize { get; set; }
        public CertificateKeyType KeyType { get; set; }
        public CertificateKeyCurveName KeyCurveName { get; set; }
        public CertificateContentType ContentType { get; set; }
    }

    public struct CertificateKeyType
    {
        public static readonly CertificateKeyType Rsa    = default;
        public static readonly CertificateKeyType RsaHsm = default;
        public static readonly CertificateKeyType Ec     = default;
        public static readonly CertificateKeyType EcHsm  = default;
        public static readonly CertificateKeyType Oct    = default;
        public static readonly CertificateKeyType OctHsm = default;
    }

    public struct CertificateKeyCurveName
    {
        public static readonly CertificateKeyCurveName P256  = default;
        public static readonly CertificateKeyCurveName P384  = default;
        public static readonly CertificateKeyCurveName P521  = default;
        public static readonly CertificateKeyCurveName P256K = default;
    }

    public struct CertificateContentType
    {
        public static readonly CertificateContentType Pkcs12 = default;
        public static readonly CertificateContentType Pem     = default;
    }

    public class KeyVaultCertificateWithPolicy { }
    public class KeyVaultCertificate       { }
    public class CertificateOperation      : Azure.Operation<KeyVaultCertificate> { }
    public class DeleteCertificateOperation           : Azure.Operation<KeyVaultCertificateWithPolicy> { }
    public class RecoverDeletedCertificateOperation    : Azure.Operation<KeyVaultCertificateWithPolicy> { }
    public class ImportCertificateOptions  { public ImportCertificateOptions(string name, byte[] certificate) { } }
    public class MergeCertificateOptions   { public MergeCertificateOptions(string name, System.Collections.Generic.IEnumerable<byte[]> x509Certificates) { } }
}

// =============================================================================
// Jose (jose-jwt NuGet package) stubs
// =============================================================================
namespace Jose
{
    public static class JWT
    {
        public static string   Encode(object payload, object key, JwsAlgorithm algorithm) => null;
        public static string   Encode(object payload, object key, JweAlgorithm algorithm, JweEncryption encryption) => null;
        public static string   EncodeBytes(byte[] payload, object key, JwsAlgorithm algorithm) => null;
        public static string   Decode(string token, object key) => null;
        public static string   Decode(string token, object key, JwsAlgorithm algorithm) => null;
        public static string   Decode(string token, object key, JweAlgorithm algorithm, JweEncryption encryption) => null;
        public static T        Decode<T>(string token, object key) => default;
        public static byte[]   DecodeBytes(string token, object key) => null;
        public static object   DecodeToObject(string token, object key) => null;
        public static string   Verify(string token, object key) => null;
        public static byte[]   VerifyBytes(string token, object key) => null;
        public static string   Decrypt(string token, object key) => null;
        public static byte[]   DecryptBytes(string token, object key) => null;
        public static string   Payload(string token) => null;
        public static byte[]   PayloadBytes(string token) => null;
        public static string   Signature(string token) => null;
        public static byte[]   SignatureBytes(string token) => null;
        public static System.Collections.Generic.IDictionary<string, object> Headers(string token) => null;
    }

    public static class JWE
    {
        public static string   Encrypt(string plaintext, JweRecipient[] recipients, JweEncryption encryption) => null;
        public static string   EncryptBytes(byte[] plaintext, JweRecipient[] recipients, JweEncryption encryption) => null;
        public static JweToken Decrypt(string token, object key) => null;
        public static JweToken Headers(string token) => null;
    }

    public class JweRecipient
    {
        public JweRecipient(JweAlgorithm algorithm, object key) { }
    }

    public class JweToken
    {
        public string   Plaintext      { get; }
        public byte[]   PlaintextBytes { get; }
        public System.Collections.Generic.IDictionary<string, object> UnprotectedHeader { get; }
    }

    public enum JwsAlgorithm
    {
        none,
        HS256, HS384, HS512,
        RS256, RS384, RS512,
        PS256, PS384, PS512,
        ES256, ES384, ES512, ES256K
    }

    public enum JweAlgorithm
    {
        RSA1_5,
        RSA_OAEP, RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512,
        DIR,
        A128KW, A192KW, A256KW,
        A128GCMKW, A192GCMKW, A256GCMKW,
        ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW,
        PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW
    }

    public enum JweEncryption
    {
        A128CBC_HS256, A192CBC_HS384, A256CBC_HS512,
        A128GCM, A192GCM, A256GCM
    }

    public enum JweCompression { DEF }
}

// =============================================================================
// Org.BouncyCastle.Bcpg — OpenPGP algorithm tag enums used by PgpCore
// =============================================================================
namespace Org.BouncyCastle.Bcpg
{
    public enum SymmetricKeyAlgorithmTag
    {
        Null, Idea, TripleDes, Cast5, Blowfish, Safer, Des,
        Aes128, Aes192, Aes256, Twofish, Camellia128, Camellia192, Camellia256
    }

    public enum HashAlgorithmTag
    {
        MD5, Sha1, RipeMD160, DoubleSha, MD2, Tiger192, Haval5pass160,
        Sha256, Sha384, Sha512, Sha224,
        MD4, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha3_256_Old, Sha3_512_Old, SM3
    }

    public enum CompressionAlgorithmTag { Uncompressed, Zip, ZLib, BZip2 }

    public enum PublicKeyAlgorithmTag
    {
        RsaGeneral, RsaEncrypt, RsaSign, ElGamalEncrypt, Dsa,
        ECDH, ECDsa, ElGamalGeneral, DiffieHellman, EdDsa,
        EdDsa_Legacy, Ed25519, Ed448, X25519, X448
    }
}

// =============================================================================
// PgpCore stubs
// =============================================================================
namespace PgpCore
{
    using Org.BouncyCastle.Bcpg;

    public interface IEncryptionKeys { }

    public class EncryptionKeys : IEncryptionKeys
    {
        public EncryptionKeys(System.IO.FileInfo publicKey) { }
        public EncryptionKeys(System.IO.FileInfo privateKey, string passphrase) { }
        public EncryptionKeys(System.IO.FileInfo publicKey, System.IO.FileInfo privateKey, string passphrase) { }
        public EncryptionKeys(System.IO.Stream publicKey) { }
        public EncryptionKeys(System.IO.Stream privateKey, string passphrase) { }
        public EncryptionKeys(System.IO.Stream publicKey, System.IO.Stream privateKey, string passphrase) { }
        public EncryptionKeys(string publicKey) { }
        public EncryptionKeys(string privateKey, string passphrase) { }
        public EncryptionKeys(string publicKey, string privateKey, string passphrase) { }
        public void UseEncryptionKey(long keyId) { }
    }

    public class EncryptionKeysBuilder
    {
        public EncryptionKeysBuilder WithPublicKey(System.IO.FileInfo publicKey) => null;
        public EncryptionKeysBuilder WithPublicKey(System.IO.Stream publicKey) => null;
        public EncryptionKeysBuilder WithPublicKey(string publicKey) => null;
        public EncryptionKeysBuilder WithPrivateKey(System.IO.FileInfo privateKey, string passphrase) => null;
        public EncryptionKeysBuilder WithPrivateKey(System.IO.Stream privateKey, string passphrase) => null;
        public EncryptionKeysBuilder WithPrivateKey(string privateKey, string passphrase) => null;
        public EncryptionKeysBuilder WithPreferredEncryptionKeyId(long keyId) => null;
        public EncryptionKeys Build() => null;
    }

    public class PgpInspectResult
    {
        public bool IsEncrypted { get; }
        public bool IsSigned { get; }
        public bool IsIntegrityProtected { get; }
        public string FileName { get; }
    }

    public class PGP : System.IDisposable
    {
        public PGP() { }
        public PGP(IEncryptionKeys encryptionKeys) { }

        public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm { get; set; }
        public HashAlgorithmTag HashAlgorithmTag { get; set; }
        public CompressionAlgorithmTag CompressionAlgorithm { get; set; }
        public PublicKeyAlgorithmTag PublicKeyAlgorithm { get; set; }
        public bool IgnoreIntegrityCheckFailure { get; set; }

        // Key generation
        public void GenerateKey(System.IO.FileInfo publicKeyFile, System.IO.FileInfo privateKeyFile,
            string username, string password, int strength = 3072, int certainty = 24) { }
        public System.Threading.Tasks.Task GenerateKeyAsync(System.IO.FileInfo publicKeyFile,
            System.IO.FileInfo privateKeyFile, string username, string password,
            int strength = 3072, int certainty = 24) => null;

        // Inspect
        public System.Threading.Tasks.Task<PgpInspectResult> InspectAsync(System.IO.FileInfo inputFile) => null;
        public System.Threading.Tasks.Task<PgpInspectResult> InspectAsync(System.IO.Stream inputStream) => null;
        public System.Threading.Tasks.Task<PgpInspectResult> InspectAsync(string input) => null;

        // Encrypt
        public System.Threading.Tasks.Task EncryptAsync(System.IO.FileInfo inputFile, System.IO.FileInfo outputFile) => null;
        public System.Threading.Tasks.Task EncryptAsync(System.IO.Stream inputStream, System.IO.Stream outputStream) => null;
        public System.Threading.Tasks.Task<string> EncryptAsync(string input) => null;

        // Sign
        public System.Threading.Tasks.Task SignAsync(System.IO.FileInfo inputFile, System.IO.FileInfo outputFile) => null;
        public System.Threading.Tasks.Task SignAsync(System.IO.Stream inputStream, System.IO.Stream outputStream) => null;
        public System.Threading.Tasks.Task<string> SignAsync(string input) => null;

        // Clear sign
        public System.Threading.Tasks.Task ClearSignAsync(System.IO.FileInfo inputFile, System.IO.FileInfo outputFile) => null;
        public System.Threading.Tasks.Task ClearSignAsync(System.IO.Stream inputStream, System.IO.Stream outputStream) => null;
        public System.Threading.Tasks.Task<string> ClearSignAsync(string input) => null;

        // Detached sign / verify
        public System.Threading.Tasks.Task SignDetachedAsync(System.IO.FileInfo inputFile, System.IO.FileInfo signatureFile) => null;
        public System.Threading.Tasks.Task SignDetachedAsync(System.IO.Stream inputStream, System.IO.Stream signatureStream) => null;
        public System.Threading.Tasks.Task<string> SignDetachedAsync(string input) => null;
        public System.Threading.Tasks.Task<bool> VerifyDetachedAsync(System.IO.FileInfo inputFile, System.IO.FileInfo signatureFile) => null;
        public System.Threading.Tasks.Task<bool> VerifyDetachedAsync(System.IO.Stream inputStream, System.IO.Stream signatureStream) => null;
        public System.Threading.Tasks.Task<bool> VerifyDetachedAsync(string input, string signature) => null;

        // Encrypt and sign
        public System.Threading.Tasks.Task EncryptAndSignAsync(System.IO.FileInfo inputFile, System.IO.FileInfo outputFile) => null;
        public System.Threading.Tasks.Task EncryptAndSignAsync(System.IO.Stream inputStream, System.IO.Stream outputStream) => null;
        public System.Threading.Tasks.Task<string> EncryptAndSignAsync(string input) => null;

        // Decrypt
        public System.Threading.Tasks.Task DecryptAsync(System.IO.FileInfo inputFile, System.IO.FileInfo outputFile) => null;
        public System.Threading.Tasks.Task DecryptAsync(System.IO.Stream inputStream, System.IO.Stream outputStream) => null;
        public System.Threading.Tasks.Task<string> DecryptAsync(string input) => null;

        // Verify
        public System.Threading.Tasks.Task<bool> VerifyAsync(System.IO.FileInfo inputFile) => null;
        public System.Threading.Tasks.Task<bool> VerifyAsync(System.IO.Stream inputStream) => null;
        public System.Threading.Tasks.Task<bool> VerifyAsync(string input) => null;

        // Verify clear
        public System.Threading.Tasks.Task<bool> VerifyClearAsync(System.IO.FileInfo inputFile) => null;
        public System.Threading.Tasks.Task<bool> VerifyClearAsync(System.IO.Stream inputStream) => null;
        public System.Threading.Tasks.Task<bool> VerifyClearAsync(string input) => null;
        public System.Threading.Tasks.Task<string> VerifyAndReadClearArmoredStringAsync(string input) => null;

        // Decrypt and verify
        public System.Threading.Tasks.Task DecryptAndVerifyAsync(System.IO.FileInfo inputFile, System.IO.FileInfo outputFile) => null;
        public System.Threading.Tasks.Task DecryptAndVerifyAsync(System.IO.Stream inputStream, System.IO.Stream outputStream) => null;
        public System.Threading.Tasks.Task<string> DecryptAndVerifyAsync(string input) => null;

        // Recipients
        public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<long>> GetRecipientsAsync(
            System.IO.FileInfo inputFile) => null;
        public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<long>> GetRecipientsAsync(
            System.IO.Stream inputStream) => null;
        public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<long>> GetRecipientsAsync(
            string input) => null;

        public void Dispose() { }
    }
}

// =============================================================================
// Microsoft.IdentityModel.Tokens stubs
// (dependency of System.IdentityModel.Tokens.Jwt and Microsoft.IdentityModel.JsonWebTokens)
// =============================================================================
namespace Microsoft.IdentityModel.Tokens
{
    public static class SecurityAlgorithms
    {
        public const string HmacSha256          = "HS256";
        public const string HmacSha256Signature = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
        public const string HmacSha384          = "HS384";
        public const string HmacSha384Signature = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";
        public const string HmacSha512          = "HS512";
        public const string HmacSha512Signature = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";
        public const string RsaSha256           = "RS256";
        public const string RsaSha256Signature  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        public const string RsaSha384           = "RS384";
        public const string RsaSha384Signature  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
        public const string RsaSha512           = "RS512";
        public const string RsaSha512Signature  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
        public const string RsaSsaPssSha256     = "PS256";
        public const string RsaSsaPssSha384     = "PS384";
        public const string RsaSsaPssSha512     = "PS512";
        public const string RsaSsaPssSha256Signature = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
        public const string RsaSsaPssSha384Signature = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";
        public const string RsaSsaPssSha512Signature = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
        public const string EcdsaSha256         = "ES256";
        public const string EcdsaSha384         = "ES384";
        public const string EcdsaSha512         = "ES512";
        public const string EcdsaSha256Signature = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
        public const string EcdsaSha384Signature = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
        public const string EcdsaSha512Signature = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
        // Note: the real Microsoft.IdentityModel.Tokens.SecurityAlgorithms has no
        // EdDsa constant — EdDSA is only usable via the raw "EdDSA" string literal.
        public const string None                = "none";
        public const string EcdhEs              = "ECDH-ES";
        public const string EcdhEsA128kw        = "ECDH-ES+A128KW";
        public const string EcdhEsA192kw        = "ECDH-ES+A192KW";
        public const string EcdhEsA256kw        = "ECDH-ES+A256KW";
        public const string Sha256              = "SHA256";
        public const string Sha384              = "SHA384";
        public const string Sha512              = "SHA512";
        public const string Sha256Digest        = "http://www.w3.org/2001/04/xmlenc#sha256";
        public const string Sha384Digest        = "http://www.w3.org/2001/04/xmldsig-more#sha384";
        public const string Sha512Digest        = "http://www.w3.org/2001/04/xmlenc#sha512";
        public const string Aes128KW            = "A128KW";
        public const string Aes128KeyWrap       = "A128KW";
        public const string Aes192KW            = "A192KW";
        public const string Aes192KeyWrap       = "A192KW";
        public const string Aes256KW            = "A256KW";
        public const string Aes256KeyWrap       = "A256KW";
        public const string RsaOAEP             = "RSA-OAEP";
        public const string RsaOAEP256          = "RSA-OAEP-256";
        public const string RsaPKCS1            = "RSA1_5";
        public const string Aes128CbcHmacSha256 = "A128CBC-HS256";
        public const string Aes192CbcHmacSha384 = "A192CBC-HS384";
        public const string Aes256CbcHmacSha512 = "A256CBC-HS512";
        public const string Aes128Gcm           = "A128GCM";
        public const string Aes192Gcm           = "A192GCM";
        public const string Aes256Gcm           = "A256GCM";
        public const string MlDsa44             = "ML-DSA-44";
        public const string MlDsa65             = "ML-DSA-65";
        public const string MlDsa87             = "ML-DSA-87";
        public const string Aes128Encryption    = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
        public const string Aes192Encryption    = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
        public const string Aes256Encryption    = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
        public const string DesEncryption       = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
        public const string RsaV15KeyWrap       = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
        public const string RsaOaepKeyWrap      = "http://www.w3.org/2001/04/xmlenc#rsa-oaep";
        public const string Ripemd160Digest     = "http://www.w3.org/2001/04/xmlenc#ripemd160";
        public const string ExclusiveC14n       = "http://www.w3.org/2001/10/xml-exc-c14n#";
        public const string ExclusiveC14nWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
        public const string EnvelopedSignature  = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    }

    public abstract class SecurityKey
    {
        public abstract int KeySize { get; }
        public string KeyId { get; set; }
    }

    public class SymmetricSecurityKey : SecurityKey
    {
        public SymmetricSecurityKey(byte[] key) { }
        public override int KeySize => 0;
    }

    public class RsaSecurityKey : SecurityKey
    {
        public RsaSecurityKey(System.Security.Cryptography.RSA rsa) { }
        public RsaSecurityKey(System.Security.Cryptography.RSAParameters rsaParameters) { }
        public override int KeySize => 0;
    }

    public class ECDsaSecurityKey : SecurityKey
    {
        public ECDsaSecurityKey(System.Security.Cryptography.ECDsa ecDsa) { }
        public override int KeySize => 0;
    }

    public class X509SecurityKey : SecurityKey
    {
        public X509SecurityKey(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate) { }
        public override int KeySize => 0;
    }

    public class JsonWebKey : SecurityKey
    {
        public JsonWebKey() { }
        public JsonWebKey(string json) { }
        public string Kty { get; set; }
        public string Alg { get; set; }
        public string Use { get; set; }
        public string Kid { get; set; }
        public override int KeySize => 0;
    }

    public class JsonWebKeySet
    {
        public JsonWebKeySet() { }
        public JsonWebKeySet(string json) { }
        public System.Collections.Generic.IList<JsonWebKey> Keys { get; }
        public static JsonWebKeySet Create(string json) => null;
    }

    public class CryptoProviderFactory
    {
        public static CryptoProviderFactory Default { get; }
        public SignatureProvider CreateForSigning(SecurityKey key, string algorithm) => null;
        public SignatureProvider CreateForVerifying(SecurityKey key, string algorithm) => null;
        public KeyWrapProvider CreateKeyWrapProviderForWrapping(SecurityKey key, string algorithm) => null;
        public KeyWrapProvider CreateKeyWrapProviderForUnwrapping(SecurityKey key, string algorithm) => null;
        public AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(SecurityKey key, string algorithm) => null;
        public HashAlgorithmProvider CreateHashAlgorithm(string algorithm) => null;
    }

    public abstract class SignatureProvider
    {
        public byte[] Sign(byte[] input) => null;
        public bool Verify(byte[] input, byte[] signature) => false;
    }

    public abstract class KeyWrapProvider
    {
        public byte[] WrapKey(byte[] keyToWrap) => null;
        public byte[] UnwrapKey(byte[] wrappedKey) => null;
    }

    public abstract class AuthenticatedEncryptionProvider
    {
        public byte[] Encrypt(byte[] plaintext, byte[] authenticatedData, out byte[] iv, out byte[] authenticationTag) { iv = null; authenticationTag = null; return null; }
        public byte[] Decrypt(byte[] ciphertext, byte[] authenticatedData, byte[] iv, byte[] authenticationTag) => null;
    }

    public abstract class HashAlgorithmProvider
    {
        public static HashAlgorithmProvider CreateHash(string algorithm) => null;
        public byte[] Hash(byte[] input) => null;
    }

    public class SigningCredentials
    {
        public SigningCredentials(SecurityKey key, string algorithm) { }
        public SigningCredentials(SecurityKey key, string algorithm, string digest) { }
        public SecurityKey Key { get; }
        public string Algorithm { get; }
        public string Digest { get; }
    }

    public class EncryptingCredentials
    {
        public EncryptingCredentials(SecurityKey key, string keyWrapAlgorithm, string dataEncryptionAlgorithm) { }
        public EncryptingCredentials(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate,
            string keyWrapAlgorithm, string dataEncryptionAlgorithm) { }
        public SecurityKey Key { get; }
        public string Alg { get; }
        public string Enc { get; }
    }

    public abstract class SecurityToken
    {
        public abstract string Id { get; }
        public abstract System.DateTime ValidFrom { get; }
        public abstract System.DateTime ValidTo { get; }
    }

    public class SecurityTokenDescriptor
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public System.Security.Claims.ClaimsIdentity Subject { get; set; }
        public System.DateTime? NotBefore { get; set; }
        public System.DateTime? Expires { get; set; }
        public System.DateTime? IssuedAt { get; set; }
        public SigningCredentials SigningCredentials { get; set; }
        public EncryptingCredentials EncryptingCredentials { get; set; }
        public System.Collections.Generic.Dictionary<string, object> Claims { get; set; }
    }

    public class TokenValidationParameters
    {
        public bool ValidateIssuer { get; set; }
        public bool ValidateAudience { get; set; }
        public bool ValidateLifetime { get; set; }
        public bool ValidateIssuerSigningKey { get; set; }
        public string ValidIssuer { get; set; }
        public System.Collections.Generic.IEnumerable<string> ValidIssuers { get; set; }
        public string ValidAudience { get; set; }
        public System.Collections.Generic.IEnumerable<string> ValidAudiences { get; set; }
        public SecurityKey IssuerSigningKey { get; set; }
        public System.Collections.Generic.IEnumerable<SecurityKey> IssuerSigningKeys { get; set; }
        public SecurityKey TokenDecryptionKey { get; set; }
        public System.Collections.Generic.IEnumerable<SecurityKey> TokenDecryptionKeys { get; set; }
        public bool RequireExpirationTime { get; set; }
    }

    public class TokenValidationResult
    {
        public bool IsValid { get; }
        public System.Security.Claims.ClaimsPrincipal ClaimsPrincipal { get; }
        public SecurityToken SecurityToken { get; }
        public System.Exception Exception { get; }
    }
}

// =============================================================================
// System.IdentityModel.Tokens.Jwt stubs
// =============================================================================
namespace System.IdentityModel.Tokens.Jwt
{
    using Microsoft.IdentityModel.Tokens;

    public class JwtHeader : System.Collections.Generic.Dictionary<string, object>
    {
        public JwtHeader() { }
        public JwtHeader(SigningCredentials signingCredentials) { }
        public JwtHeader(SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials) { }
        public string Alg { get; }
        public string Kid { get; }
        public string Typ { get; }
        public string Enc { get; }
    }

    public class JwtPayload : System.Collections.Generic.Dictionary<string, object>
    {
        public JwtPayload() { }
        public JwtPayload(System.Collections.Generic.IEnumerable<System.Security.Claims.Claim> claims) { }
        public JwtPayload(string issuer, string audience,
            System.Collections.Generic.IEnumerable<System.Security.Claims.Claim> claims,
            System.DateTime? notBefore, System.DateTime? expires) { }
        public string Iss { get; set; }
        public string Sub { get; set; }
        public string Aud { get; set; }
        public long Exp { get; set; }
        public long Iat { get; set; }
    }

    public class JwtSecurityToken : SecurityToken
    {
        public JwtSecurityToken(string jwtEncodedString) { }
        public JwtSecurityToken(JwtHeader header, JwtPayload payload) { }
        public JwtSecurityToken(
            string issuer = null, string audience = null,
            System.Collections.Generic.IEnumerable<System.Security.Claims.Claim> claims = null,
            System.DateTime? notBefore = null, System.DateTime? expires = null,
            SigningCredentials signingCredentials = null) { }
        public override string Id => null;
        public override System.DateTime ValidFrom => default;
        public override System.DateTime ValidTo => default;
        public JwtHeader Header { get; }
        public JwtPayload Payload { get; }
        public string RawHeader { get; }
        public string RawPayload { get; }
        public string RawSignature { get; }
        public System.Collections.Generic.IEnumerable<System.Security.Claims.Claim> Claims { get; }
    }

    public class JwtSecurityTokenHandler
    {
        public JwtSecurityToken CreateJwtSecurityToken(SecurityTokenDescriptor tokenDescriptor) => null;
        public JwtSecurityToken CreateJwtSecurityToken(
            string issuer = null, string audience = null,
            System.Security.Claims.ClaimsIdentity subject = null,
            System.DateTime? notBefore = null, System.DateTime? expires = null,
            System.DateTime? issuedAt = null,
            SigningCredentials signingCredentials = null) => null;
        public JwtSecurityToken CreateJwtSecurityToken(
            string issuer, string audience,
            System.Security.Claims.ClaimsIdentity subject,
            System.DateTime? notBefore, System.DateTime? expires,
            System.DateTime? issuedAt,
            SigningCredentials signingCredentials,
            EncryptingCredentials encryptingCredentials) => null;
        public string CreateEncodedJwt(SecurityTokenDescriptor tokenDescriptor) => null;
        public SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor) => null;
        public string WriteToken(SecurityToken token) => null;
        public string DecryptToken(JwtSecurityToken token, TokenValidationParameters validationParameters) => null;
        public bool ValidateSignature(string token, TokenValidationParameters validationParameters) => false;
        public System.Security.Claims.ClaimsPrincipal ValidateToken(
            string token, TokenValidationParameters validationParameters,
            out SecurityToken validatedToken) { validatedToken = null; return null; }
        public System.Threading.Tasks.Task<TokenValidationResult> ValidateTokenAsync(
            string token, TokenValidationParameters validationParameters) => null;
        public JwtSecurityToken ReadJwtToken(string token) => null;
        public SecurityToken ReadToken(string tokenString) => null;
        public bool CanReadToken(string tokenString) => false;
    }
}

// =============================================================================
// Microsoft.IdentityModel.JsonWebTokens stubs (newer async-first handler)
// =============================================================================
namespace Microsoft.IdentityModel.JsonWebTokens
{
    using Microsoft.IdentityModel.Tokens;

    public class JsonWebToken : SecurityToken
    {
        public JsonWebToken(string jwtEncodedString) { }
        public override string Id => null;
        public override System.DateTime ValidFrom => default;
        public override System.DateTime ValidTo => default;
        public string Issuer { get; }
        public string Subject { get; }
        public System.Collections.Generic.IEnumerable<System.Security.Claims.Claim> Claims { get; }
    }

    public class JsonWebTokenHandler
    {
        public string CreateToken(SecurityTokenDescriptor tokenDescriptor) => null;
        public System.Threading.Tasks.Task<string> CreateTokenAsync(SecurityTokenDescriptor tokenDescriptor) => null;
        public TokenValidationResult ValidateToken(
            string token, TokenValidationParameters validationParameters) => null;
        public System.Threading.Tasks.Task<TokenValidationResult> ValidateTokenAsync(
            string token, TokenValidationParameters validationParameters) => null;
        public JsonWebToken ReadJsonWebToken(string token) => null;
        public bool CanReadToken(string token) => false;
    }
}

// =============================================================================
// System.Security.Cryptography — post-quantum types from Microsoft.Bcl.Cryptography
// (MLDsa, MLKem, SlhDsa, CompositeMLDsa are .NET 10+ — not in .NET 8 BCL)
// SP800108HmacCounterKdf is in .NET 7+ BCL and needs no stub.
// =============================================================================
namespace System.Security.Cryptography
{
    // -------------------------------------------------------------------------
    // ML-DSA algorithm identifiers (FIPS 204)
    // -------------------------------------------------------------------------
    public sealed class MLDsaAlgorithm
    {
        public static MLDsaAlgorithm MLDsa44 { get; }
        public static MLDsaAlgorithm MLDsa65 { get; }
        public static MLDsaAlgorithm MLDsa87 { get; }
        public string Name { get; }
        public int PublicKeySizeInBytes { get; }
        public int PrivateKeySizeInBytes { get; }
        public int PrivateSeedSizeInBytes { get; }
        public int SignatureSizeInBytes { get; }
    }

    // -------------------------------------------------------------------------
    // ML-DSA key (FIPS 204 — CRYSTALS-Dilithium)
    // -------------------------------------------------------------------------
    public class MLDsa : System.IDisposable
    {
        // Static factories
        public static MLDsa GenerateKey(MLDsaAlgorithm algorithm) => null;
        public static MLDsa ImportMLDsaPublicKey(MLDsaAlgorithm algorithm, byte[] source) => null;
        public static MLDsa ImportMLDsaPublicKey(MLDsaAlgorithm algorithm, System.ReadOnlySpan<byte> source) => null;
        public static MLDsa ImportMLDsaPrivateKey(MLDsaAlgorithm algorithm, byte[] source) => null;
        public static MLDsa ImportMLDsaPrivateKey(MLDsaAlgorithm algorithm, System.ReadOnlySpan<byte> source) => null;
        public static MLDsa ImportMLDsaPrivateSeed(MLDsaAlgorithm algorithm, byte[] source) => null;
        public static MLDsa ImportSubjectPublicKeyInfo(byte[] source) => null;
        public static MLDsa ImportPkcs8PrivateKey(byte[] source) => null;
        public static MLDsa ImportFromPem(string input) => null;
        public static MLDsa ImportEncryptedPkcs8PrivateKey(byte[] passwordBytes, byte[] source) => null;
        public static MLDsa ImportEncryptedPkcs8PrivateKey(string password, byte[] source) => null;
        public static MLDsa ImportFromEncryptedPem(string input, byte[] passwordBytes) => null;
        public static MLDsa ImportFromEncryptedPem(string input, string password) => null;
        // Signing
        public byte[] SignData(byte[] data, byte[] context = null) => null;
        public byte[] SignPreHash(byte[] hash, string hashOid, byte[] context = null) => null;
        public byte[] SignMu(byte[] mu) => null;
        // Verification
        public bool VerifyData(byte[] data, byte[] signature, byte[] context = null) => false;
        public bool VerifyPreHash(byte[] hash, byte[] signature, string hashOid, byte[] context = null) => false;
        public bool VerifyMu(byte[] mu, byte[] signature) => false;
        // Export
        public byte[] ExportMLDsaPublicKey() => null;
        public byte[] ExportMLDsaPrivateKey() => null;
        public byte[] ExportMLDsaPrivateSeed() => null;
        public byte[] ExportSubjectPublicKeyInfo() => null;
        public byte[] ExportPkcs8PrivateKey() => null;
        public string ExportSubjectPublicKeyInfoPem() => null;
        public string ExportPkcs8PrivateKeyPem() => null;
        public byte[] ExportEncryptedPkcs8PrivateKey(byte[] passwordBytes, PbeParameters pbeParameters) => null;
        public byte[] ExportEncryptedPkcs8PrivateKey(string password, PbeParameters pbeParameters) => null;
        public string ExportEncryptedPkcs8PrivateKeyPem(byte[] passwordBytes, PbeParameters pbeParameters) => null;
        public string ExportEncryptedPkcs8PrivateKeyPem(string password, PbeParameters pbeParameters) => null;
        public bool TryExportEncryptedPkcs8PrivateKey(byte[] passwordBytes, PbeParameters pbeParameters, System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportMLDsaPublicKey(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportMLDsaPrivateKey(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportMLDsaPrivateSeed(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportSubjectPublicKeyInfo(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportPkcs8PrivateKey(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        // Properties
        public MLDsaAlgorithm Algorithm { get; }
        public static bool IsSupported { get; }
        public void Dispose() { }
    }

    // -------------------------------------------------------------------------
    // ML-KEM algorithm identifiers (FIPS 203)
    // -------------------------------------------------------------------------
    public sealed class MLKemAlgorithm
    {
        public static MLKemAlgorithm MLKem512  { get; }
        public static MLKemAlgorithm MLKem768  { get; }
        public static MLKemAlgorithm MLKem1024 { get; }
        public string Name { get; }
        public int EncapsulationKeySizeInBytes { get; }
        public int DecapsulationKeySizeInBytes { get; }
        public int CiphertextSizeInBytes { get; }
        public int SharedSecretSizeInBytes { get; }
        public int PrivateSeedSizeInBytes { get; }
    }

    // -------------------------------------------------------------------------
    // ML-KEM key (FIPS 203 — CRYSTALS-Kyber)
    // -------------------------------------------------------------------------
    public class MLKem : System.IDisposable
    {
        // Static factories
        public static MLKem GenerateKey(MLKemAlgorithm algorithm) => null;
        public static MLKem ImportEncapsulationKey(MLKemAlgorithm algorithm, byte[] source) => null;
        public static MLKem ImportEncapsulationKey(MLKemAlgorithm algorithm, System.ReadOnlySpan<byte> source) => null;
        public static MLKem ImportDecapsulationKey(MLKemAlgorithm algorithm, byte[] source) => null;
        public static MLKem ImportDecapsulationKey(MLKemAlgorithm algorithm, System.ReadOnlySpan<byte> source) => null;
        public static MLKem ImportPrivateSeed(MLKemAlgorithm algorithm, byte[] source) => null;
        public static MLKem ImportSubjectPublicKeyInfo(byte[] source) => null;
        public static MLKem ImportPkcs8PrivateKey(byte[] source) => null;
        public static MLKem ImportFromPem(string input) => null;
        public static MLKem ImportEncryptedPkcs8PrivateKey(byte[] passwordBytes, byte[] source) => null;
        public static MLKem ImportEncryptedPkcs8PrivateKey(string password, byte[] source) => null;
        public static MLKem ImportFromEncryptedPem(string input, byte[] passwordBytes) => null;
        public static MLKem ImportFromEncryptedPem(string input, string password) => null;
        // KEM operations
        public void Encapsulate(out byte[] ciphertext, out byte[] sharedSecret) { ciphertext = null; sharedSecret = null; }
        public byte[] Decapsulate(byte[] ciphertext) => null;
        // Export
        public byte[] ExportEncapsulationKey() => null;
        public byte[] ExportDecapsulationKey() => null;
        public byte[] ExportPrivateSeed() => null;
        public byte[] ExportSubjectPublicKeyInfo() => null;
        public byte[] ExportPkcs8PrivateKey() => null;
        public string ExportSubjectPublicKeyInfoPem() => null;
        public string ExportPkcs8PrivateKeyPem() => null;
        public byte[] ExportEncryptedPkcs8PrivateKey(byte[] passwordBytes, PbeParameters pbeParameters) => null;
        public byte[] ExportEncryptedPkcs8PrivateKey(string password, PbeParameters pbeParameters) => null;
        public string ExportEncryptedPkcs8PrivateKeyPem(byte[] passwordBytes, PbeParameters pbeParameters) => null;
        public string ExportEncryptedPkcs8PrivateKeyPem(string password, PbeParameters pbeParameters) => null;
        public bool TryExportEncryptedPkcs8PrivateKey(byte[] passwordBytes, PbeParameters pbeParameters, System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportEncapsulationKey(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportDecapsulationKey(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportPrivateSeed(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportSubjectPublicKeyInfo(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportPkcs8PrivateKey(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        // Properties
        public MLKemAlgorithm Algorithm { get; }
        public static bool IsSupported { get; }
        public void Dispose() { }
    }

    // -------------------------------------------------------------------------
    // SLH-DSA algorithm identifiers (FIPS 205) — 12 parameter sets
    // -------------------------------------------------------------------------
    public sealed class SlhDsaAlgorithm
    {
        // SHA-2 parameter sets (s=small, f=fast)
        public static SlhDsaAlgorithm SlhDsaSha2_128s { get; }
        public static SlhDsaAlgorithm SlhDsaSha2_128f { get; }
        public static SlhDsaAlgorithm SlhDsaSha2_192s { get; }
        public static SlhDsaAlgorithm SlhDsaSha2_192f { get; }
        public static SlhDsaAlgorithm SlhDsaSha2_256s { get; }
        public static SlhDsaAlgorithm SlhDsaSha2_256f { get; }
        // SHAKE parameter sets
        public static SlhDsaAlgorithm SlhDsaShake128s { get; }
        public static SlhDsaAlgorithm SlhDsaShake128f { get; }
        public static SlhDsaAlgorithm SlhDsaShake192s { get; }
        public static SlhDsaAlgorithm SlhDsaShake192f { get; }
        public static SlhDsaAlgorithm SlhDsaShake256s { get; }
        public static SlhDsaAlgorithm SlhDsaShake256f { get; }
        public string Name { get; }
        public int PublicKeySizeInBytes { get; }
        public int PrivateKeySizeInBytes { get; }
        public int SignatureSizeInBytes { get; }
    }

    // -------------------------------------------------------------------------
    // SLH-DSA key (FIPS 205 — SPHINCS+)
    // -------------------------------------------------------------------------
    public class SlhDsa : System.IDisposable
    {
        // Static factories
        public static SlhDsa GenerateKey(SlhDsaAlgorithm algorithm) => null;
        public static SlhDsa ImportSlhDsaPublicKey(SlhDsaAlgorithm algorithm, byte[] source) => null;
        public static SlhDsa ImportSlhDsaPrivateKey(SlhDsaAlgorithm algorithm, byte[] source) => null;
        public static SlhDsa ImportSubjectPublicKeyInfo(byte[] source) => null;
        public static SlhDsa ImportPkcs8PrivateKey(byte[] source) => null;
        public static SlhDsa ImportFromPem(string input) => null;
        public static SlhDsa ImportEncryptedPkcs8PrivateKey(byte[] passwordBytes, byte[] source) => null;
        public static SlhDsa ImportEncryptedPkcs8PrivateKey(string password, byte[] source) => null;
        public static SlhDsa ImportFromEncryptedPem(string input, byte[] passwordBytes) => null;
        public static SlhDsa ImportFromEncryptedPem(string input, string password) => null;
        // Signing
        public byte[] SignData(byte[] data, byte[] context = null) => null;
        public byte[] SignPreHash(byte[] hash, string hashOid, byte[] context = null) => null;
        // Verification
        public bool VerifyData(byte[] data, byte[] signature, byte[] context = null) => false;
        public bool VerifyPreHash(byte[] hash, byte[] signature, string hashOid, byte[] context = null) => false;
        // Export
        public byte[] ExportSlhDsaPublicKey() => null;
        public byte[] ExportSlhDsaPrivateKey() => null;
        public byte[] ExportSubjectPublicKeyInfo() => null;
        public byte[] ExportPkcs8PrivateKey() => null;
        public string ExportSubjectPublicKeyInfoPem() => null;
        public string ExportPkcs8PrivateKeyPem() => null;
        public byte[] ExportEncryptedPkcs8PrivateKey(byte[] passwordBytes, PbeParameters pbeParameters) => null;
        public byte[] ExportEncryptedPkcs8PrivateKey(string password, PbeParameters pbeParameters) => null;
        public string ExportEncryptedPkcs8PrivateKeyPem(byte[] passwordBytes, PbeParameters pbeParameters) => null;
        public string ExportEncryptedPkcs8PrivateKeyPem(string password, PbeParameters pbeParameters) => null;
        public bool TryExportEncryptedPkcs8PrivateKey(byte[] passwordBytes, PbeParameters pbeParameters, System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportSlhDsaPublicKey(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportSlhDsaPrivateKey(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportSubjectPublicKeyInfo(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportPkcs8PrivateKey(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        // Properties
        public SlhDsaAlgorithm Algorithm { get; }
        public static bool IsSupported { get; }
        public void Dispose() { }
    }

    // -------------------------------------------------------------------------
    // Composite ML-DSA algorithm identifiers and key
    // (ML-DSA combined with a classical algorithm — experimental)
    // -------------------------------------------------------------------------
    public sealed class CompositeMLDsaAlgorithm
    {
        public string Name { get; }
        // Named algorithm property examples (actual set may vary by .NET version)
        public static CompositeMLDsaAlgorithm MLDsa44WithEd25519   { get; }
        public static CompositeMLDsaAlgorithm MLDsa65WithEcdsaP256  { get; }
        public static CompositeMLDsaAlgorithm MLDsa87WithEcdsaP384  { get; }
        public static CompositeMLDsaAlgorithm MLDsa65WithRsa2048    { get; }
    }

    public class CompositeMLDsa : System.IDisposable
    {
        public static CompositeMLDsa GenerateKey(CompositeMLDsaAlgorithm algorithm) => null;
        public static CompositeMLDsa ImportSubjectPublicKeyInfo(byte[] source) => null;
        public static CompositeMLDsa ImportPkcs8PrivateKey(byte[] source) => null;
        public static CompositeMLDsa ImportFromPem(string input) => null;
        public static CompositeMLDsa ImportEncryptedPkcs8PrivateKey(byte[] passwordBytes, byte[] source) => null;
        public static CompositeMLDsa ImportEncryptedPkcs8PrivateKey(string password, byte[] source) => null;
        public static CompositeMLDsa ImportFromEncryptedPem(string input, byte[] passwordBytes) => null;
        public static CompositeMLDsa ImportFromEncryptedPem(string input, string password) => null;
        public static CompositeMLDsa ImportCompositeMLDsaPrivateKey(CompositeMLDsaAlgorithm algorithm, byte[] source) => null;
        public static CompositeMLDsa ImportCompositeMLDsaPublicKey(CompositeMLDsaAlgorithm algorithm, byte[] source) => null;
        public byte[] SignData(byte[] data, byte[] context = null) => null;
        public byte[] SignPreHash(byte[] hash, string hashOid, byte[] context = null) => null;
        public bool VerifyData(byte[] data, byte[] signature, byte[] context = null) => false;
        public bool VerifyPreHash(byte[] hash, byte[] signature, string hashOid, byte[] context = null) => false;
        public byte[] ExportCompositeMLDsaPrivateKey() => null;
        public byte[] ExportCompositeMLDsaPublicKey() => null;
        public bool TryExportCompositeMLDsaPrivateKey(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public bool TryExportCompositeMLDsaPublicKey(System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public byte[] ExportSubjectPublicKeyInfo() => null;
        public byte[] ExportPkcs8PrivateKey() => null;
        public string ExportSubjectPublicKeyInfoPem() => null;
        public string ExportPkcs8PrivateKeyPem() => null;
        public byte[] ExportEncryptedPkcs8PrivateKey(byte[] passwordBytes, PbeParameters pbeParameters) => null;
        public byte[] ExportEncryptedPkcs8PrivateKey(string password, PbeParameters pbeParameters) => null;
        public string ExportEncryptedPkcs8PrivateKeyPem(byte[] passwordBytes, PbeParameters pbeParameters) => null;
        public string ExportEncryptedPkcs8PrivateKeyPem(string password, PbeParameters pbeParameters) => null;
        public bool TryExportEncryptedPkcs8PrivateKey(byte[] passwordBytes, PbeParameters pbeParameters, System.Span<byte> destination, out int bytesWritten) { bytesWritten = 0; return false; }
        public CompositeMLDsaAlgorithm Algorithm { get; }
        public static bool IsSupported { get; }
        public void Dispose() { }
    }
}

// =============================================================================
// Azure.Identity — credential implementations
// =============================================================================
namespace Azure.Identity
{
    public class DefaultAzureCredential      : Azure.Core.TokenCredential { }
    public class ClientSecretCredential      : Azure.Core.TokenCredential
    {
        public ClientSecretCredential(string tenantId, string clientId, string clientSecret) { }
    }
    public class ClientCertificateCredential : Azure.Core.TokenCredential
    {
        public ClientCertificateCredential(string tenantId, string clientId, System.Security.Cryptography.X509Certificates.X509Certificate2 cert) { }
    }
    public class ManagedIdentityCredential   : Azure.Core.TokenCredential { }
    public class WorkloadIdentityCredential  : Azure.Core.TokenCredential { }
    public class EnvironmentCredential       : Azure.Core.TokenCredential { }
    public class InteractiveBrowserCredential : Azure.Core.TokenCredential { }
    public class AzureCliCredential          : Azure.Core.TokenCredential { }
    public class ChainedTokenCredential      : Azure.Core.TokenCredential
    {
        public ChainedTokenCredential(params Azure.Core.TokenCredential[] sources) { }
    }
}

// =============================================================================
// Org.BouncyCastle.Math
// =============================================================================
namespace Org.BouncyCastle.Math
{
    public class BigInteger
    {
        public static readonly BigInteger Zero;
        public static readonly BigInteger One;
        public BigInteger(string value) { }
        public BigInteger(string value, int radix) { }
        public BigInteger(int bitLength, System.Random rnd) { }
        public BigInteger(byte[] bytes) { }
        public BigInteger Add(BigInteger value) => null;
        public BigInteger Subtract(BigInteger value) => null;
        public BigInteger Multiply(BigInteger value) => null;
        public BigInteger Mod(BigInteger m) => null;
        public BigInteger ModPow(BigInteger exponent, BigInteger m) => null;
        public int BitLength { get; }
        public byte[] ToByteArray() => null;
    }
}

// =============================================================================
// Org.BouncyCastle.Math.EC — elliptic curve math base types
// =============================================================================
namespace Org.BouncyCastle.Math.EC
{
    public abstract class ECCurve { }
    public abstract class ECPoint { }
}

// =============================================================================
// Org.BouncyCastle.Asn1 — minimal base types required by Asn1.X9 / Asn1.Nist
// =============================================================================
namespace Org.BouncyCastle.Asn1
{
    public class DerObjectIdentifier
    {
        public DerObjectIdentifier(string id) { }
        public string Id { get; }
    }
}

// =============================================================================
// Org.BouncyCastle.Asn1.X9 — X9 elliptic curve definitions
// =============================================================================
namespace Org.BouncyCastle.Asn1.X9
{
    public class X9ECParameters
    {
        public Org.BouncyCastle.Math.EC.ECCurve Curve { get; }
        public Org.BouncyCastle.Math.EC.ECPoint G { get; }
        public Org.BouncyCastle.Math.BigInteger N { get; }
    }
    public class ECNamedCurveTable
    {
        public static X9ECParameters GetByName(string name) => null;
        public static X9ECParameters GetByOid(Org.BouncyCastle.Asn1.DerObjectIdentifier oid) => null;
        public static Org.BouncyCastle.Asn1.DerObjectIdentifier GetOid(string name) => null;
    }
    public class X9ObjectIdentifiers
    {
        public static readonly Org.BouncyCastle.Asn1.DerObjectIdentifier Prime256v1;
        public static readonly Org.BouncyCastle.Asn1.DerObjectIdentifier Secp384r1;
        public static readonly Org.BouncyCastle.Asn1.DerObjectIdentifier Secp521r1;
    }
}

// =============================================================================
// Org.BouncyCastle.Asn1.Nist — NIST named curves
// =============================================================================
namespace Org.BouncyCastle.Asn1.Nist
{
    public class NistNamedCurves
    {
        public static Org.BouncyCastle.Asn1.X9.X9ECParameters GetByName(string name) => null;
        public static Org.BouncyCastle.Asn1.X9.X9ECParameters GetByOid(Org.BouncyCastle.Asn1.DerObjectIdentifier oid) => null;
    }
    public class NistObjectIdentifiers
    {
        public static readonly Org.BouncyCastle.Asn1.DerObjectIdentifier IdAes128Cbc;
        public static readonly Org.BouncyCastle.Asn1.DerObjectIdentifier IdAes192Cbc;
        public static readonly Org.BouncyCastle.Asn1.DerObjectIdentifier IdAes256Cbc;
        public static readonly Org.BouncyCastle.Asn1.DerObjectIdentifier IdAes128Gcm;
        public static readonly Org.BouncyCastle.Asn1.DerObjectIdentifier IdAes256Gcm;
    }
}

// =============================================================================
// Org.BouncyCastle.Crypto.Parameters — key and cipher parameter types
// =============================================================================
namespace Org.BouncyCastle.Crypto.Parameters
{
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Math;

    public class KeyParameter : ICipherParameters
    {
        public KeyParameter(byte[] key) { }
        public KeyParameter(byte[] key, int keyOff, int keyLen) { }
        public byte[] GetKey() => null;
    }
    public class ParametersWithIV : ICipherParameters
    {
        public ParametersWithIV(ICipherParameters parameters, byte[] iv) { }
        public ICipherParameters Parameters { get; }
        public byte[] GetIV() => null;
    }
    public class AEADParameters : ICipherParameters
    {
        public AEADParameters(KeyParameter key, int macSize, byte[] nonce) { }
        public AEADParameters(KeyParameter key, int macSize, byte[] nonce, byte[] associatedText) { }
        public KeyParameter Key { get; }
        public byte[] GetNonce() => null;
        public byte[] GetAssociatedText() => null;
        public int MacSize { get; }
    }
    public class ECDomainParameters
    {
        public ECDomainParameters(Org.BouncyCastle.Math.EC.ECCurve curve, Org.BouncyCastle.Math.EC.ECPoint g, BigInteger n) { }
    }
    public class ECKeyGenerationParameters : KeyGenerationParameters
    {
        public ECKeyGenerationParameters(ECDomainParameters domainParameters, Org.BouncyCastle.Security.SecureRandom random)
            : base(random, 0) { }
        public ECDomainParameters DomainParameters { get; }
    }
    public class ECPublicKeyParameters  : AsymmetricKeyParameter
    {
        public ECPublicKeyParameters(Org.BouncyCastle.Math.EC.ECPoint q, ECDomainParameters parameters)
            : base(false) { }
        public Org.BouncyCastle.Math.EC.ECPoint Q { get; }
    }
    public class ECPrivateKeyParameters : AsymmetricKeyParameter
    {
        public ECPrivateKeyParameters(BigInteger d, ECDomainParameters parameters)
            : base(true) { }
        public BigInteger D { get; }
    }
    public class RsaKeyParameters : AsymmetricKeyParameter
    {
        public RsaKeyParameters(bool isPrivate, BigInteger modulus, BigInteger exponent)
            : base(isPrivate) { }
        public BigInteger Modulus { get; }
        public BigInteger Exponent { get; }
    }
    public class RsaPrivateCrtKeyParameters : RsaKeyParameters
    {
        public RsaPrivateCrtKeyParameters(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, BigInteger p, BigInteger q, BigInteger dP, BigInteger dQ, BigInteger qInv)
            : base(true, modulus, privateExponent) { }
    }
    public class DsaParameters
    {
        public DsaParameters(BigInteger p, BigInteger q, BigInteger g) { }
    }
    public class DsaPublicKeyParameters  : AsymmetricKeyParameter
    {
        public DsaPublicKeyParameters(BigInteger y, DsaParameters parameters)
            : base(false) { }
    }
    public class DsaPrivateKeyParameters : AsymmetricKeyParameter
    {
        public DsaPrivateKeyParameters(BigInteger x, DsaParameters parameters)
            : base(true) { }
    }
    public class DHParameters
    {
        public DHParameters(BigInteger p, BigInteger g) { }
    }
    public class DHPublicKeyParameters  : AsymmetricKeyParameter
    {
        public DHPublicKeyParameters(BigInteger y, DHParameters parameters)
            : base(false) { }
    }
    public class DHPrivateKeyParameters : AsymmetricKeyParameter
    {
        public DHPrivateKeyParameters(BigInteger x, DHParameters parameters)
            : base(true) { }
    }
    public class Ed25519PublicKeyParameters  : AsymmetricKeyParameter
    {
        public Ed25519PublicKeyParameters(byte[] buf, int off) : base(false) { }
    }
    public class Ed25519PrivateKeyParameters : AsymmetricKeyParameter
    {
        public Ed25519PrivateKeyParameters(byte[] buf, int off) : base(true) { }
        public Ed25519PublicKeyParameters GeneratePublicKey() => null;
    }
    public class X25519PublicKeyParameters  : AsymmetricKeyParameter
    {
        public X25519PublicKeyParameters(byte[] buf, int off) : base(false) { }
    }
    public class X25519PrivateKeyParameters : AsymmetricKeyParameter
    {
        public X25519PrivateKeyParameters(byte[] buf, int off) : base(true) { }
        public X25519PublicKeyParameters GeneratePublicKey() => null;
    }
    public class KeyGenerationParameters
    {
        protected KeyGenerationParameters(Org.BouncyCastle.Security.SecureRandom random, int strength) { }
    }
    public class RsaKeyGenerationParameters : KeyGenerationParameters
    {
        public RsaKeyGenerationParameters(BigInteger publicExponent, Org.BouncyCastle.Security.SecureRandom random, int strength, int certainty)
            : base(random, strength) { }
    }
}

// =============================================================================
// Org.BouncyCastle.Crypto.Paddings
// =============================================================================
namespace Org.BouncyCastle.Crypto.Paddings
{
    using Org.BouncyCastle.Crypto;

    public interface IBlockCipherPadding { }
    public class PaddedBufferedBlockCipher : IBufferedCipher
    {
        public PaddedBufferedBlockCipher(IBlockCipher cipher) { }
        public PaddedBufferedBlockCipher(IBlockCipher cipher, IBlockCipherPadding padding) { }
    }
    public class Pkcs7Padding      : IBlockCipherPadding { }
    public class ZeroBytePadding   : IBlockCipherPadding { }
    public class X923Padding       : IBlockCipherPadding { }
    public class ISO10126d2Padding : IBlockCipherPadding { }
    public class TbcPadding        : IBlockCipherPadding { }
}

// =============================================================================
// System.Security.Cryptography — algorithms removed from modern .NET
// =============================================================================
namespace System.Security.Cryptography
{
    public abstract class RIPEMD160 : HashAlgorithm
    {
        public static new RIPEMD160 Create() => null;
        public static new RIPEMD160 Create(string algName) => null;
    }
    public sealed class RIPEMD160Managed : RIPEMD160
    {
        protected override void HashCore(byte[] array, int ibStart, int cbSize) { }
        protected override byte[] HashFinal() => null;
        public override void Initialize() { }
    }
    public class HMACRIPEMD160 : HMAC
    {
        public HMACRIPEMD160() { }
        public HMACRIPEMD160(byte[] key) { }
    }
}

// =============================================================================
// System.Security.Cryptography — DPAPI
// Ships as the System.Security.Cryptography.ProtectedData package, so these
// types are absent from the net8.0 reference set.
// =============================================================================
namespace System.Security.Cryptography
{
    public enum DataProtectionScope { CurrentUser, LocalMachine }
    public enum MemoryProtectionScope { SameProcess, CrossProcess, SameLogon }

    public static class ProtectedData
    {
        public static byte[] Protect(byte[] userData, byte[] optionalEntropy, DataProtectionScope scope) => null;
        public static byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, DataProtectionScope scope) => null;
    }

    public static class ProtectedMemory
    {
        public static void Protect(byte[] userData, MemoryProtectionScope scope) { }
        public static void Unprotect(byte[] encryptedData, MemoryProtectionScope scope) { }
    }
}

// =============================================================================
// System.Security.Cryptography.Xml (System.Security.Cryptography.Xml package)
// =============================================================================
namespace System.Security.Cryptography.Xml
{
    using System.Security.Cryptography;
    using System.Xml;

    public class Reference
    {
        public Reference() { }
        public Reference(string uri) { }
        public string DigestMethod { get; set; }
        public string Uri { get; set; }
    }

    public class SignedInfo
    {
        public string SignatureMethod { get; set; }
        public string CanonicalizationMethod { get; set; }
    }

    public class KeyInfo { }

    public class SignedXml
    {
        public const string XmlDsigSHA1Url = "";
        public const string XmlDsigSHA256Url = "";
        public const string XmlDsigSHA384Url = "";
        public const string XmlDsigSHA512Url = "";
        public const string XmlDsigDSAUrl = "";
        public const string XmlDsigHMACSHA1Url = "";
        public const string XmlDsigRSASHA1Url = "";
        public const string XmlDsigRSASHA256Url = "";
        public const string XmlDsigRSASHA384Url = "";
        public const string XmlDsigRSASHA512Url = "";

        public SignedXml() { }
        public SignedXml(XmlDocument document) { }
        public SignedXml(XmlElement element) { }
        public AsymmetricAlgorithm SigningKey { get; set; }
        public SignedInfo SignedInfo { get; }
        public KeyInfo KeyInfo { get; set; }
        public void AddReference(Reference reference) { }
        public void ComputeSignature() { }
        public void ComputeSignature(KeyedHashAlgorithm macAlg) { }
        public bool CheckSignature() => false;
        public bool CheckSignature(AsymmetricAlgorithm key) => false;
        public XmlElement GetXml() => null;
    }

    public class EncryptedData
    {
        public string Type { get; set; }
        public byte[] CipherData { get; set; }
    }

    public class EncryptedXml
    {
        public const string XmlEncAES128Url = "";
        public const string XmlEncAES192Url = "";
        public const string XmlEncAES256Url = "";
        public const string XmlEncTripleDESUrl = "";
        public const string XmlEncDESUrl = "";
        public const string XmlEncAES128KeyWrapUrl = "";
        public const string XmlEncAES192KeyWrapUrl = "";
        public const string XmlEncAES256KeyWrapUrl = "";
        public const string XmlEncTripleDESKeyWrapUrl = "";
        public const string XmlEncRSA15Url = "";
        public const string XmlEncRSAOAEPUrl = "";

        public EncryptedXml() { }
        public EncryptedXml(XmlDocument document) { }
        public byte[] EncryptData(byte[] plaintext, SymmetricAlgorithm symmetricAlgorithm) => null;
        public byte[] EncryptData(XmlElement inputElement, SymmetricAlgorithm symmetricAlgorithm, bool content) => null;
        public EncryptedData Encrypt(XmlElement inputElement, X509Certificates.X509Certificate2 certificate) => null;
        public byte[] DecryptData(EncryptedData encryptedData, SymmetricAlgorithm symmetricAlgorithm) => null;
        public byte[] DecryptKey(byte[] keyData, SymmetricAlgorithm symmetricAlgorithm) => null;
        public void DecryptDocument() { }
        public static byte[] EncryptKey(byte[] keyData, SymmetricAlgorithm symmetricAlgorithm) => null;
    }
}

// =============================================================================
// System.Security.Cryptography.Pkcs (CMS / PKCS#7, PKCS#12, RFC 3161)
// =============================================================================
namespace System.Security.Cryptography.Pkcs
{
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    public sealed class ContentInfo
    {
        public ContentInfo(byte[] content) { }
        public ContentInfo(Oid contentType, byte[] content) { }
        public byte[] Content { get; }
        public Oid ContentType { get; }
    }

    public sealed class CmsSigner
    {
        public CmsSigner() { }
        public CmsSigner(X509Certificate2 certificate) { }
        public X509Certificate2 Certificate { get; set; }
        public Oid DigestAlgorithm { get; set; }
        public RSASignaturePadding SignaturePadding { get; set; }
    }

    public sealed class CmsRecipient
    {
        public CmsRecipient(X509Certificate2 certificate) { }
        public CmsRecipient(SubjectIdentifierType recipientIdentifierType, X509Certificate2 certificate) { }
    }

    public enum SubjectIdentifierType { Unknown, IssuerAndSerialNumber, SubjectKeyIdentifier, NoSignature }

    public sealed class SignedCms
    {
        public SignedCms() { }
        public SignedCms(ContentInfo contentInfo) { }
        public SignedCms(ContentInfo contentInfo, bool detached) { }
        public ContentInfo ContentInfo { get; }
        public void ComputeSignature() { }
        public void ComputeSignature(CmsSigner signer) { }
        public void ComputeSignature(CmsSigner signer, bool silent) { }
        public void CheckSignature(bool verifySignatureOnly) { }
        public void CheckSignature(X509Certificate2Collection extraStore, bool verifySignatureOnly) { }
        public void Decode(byte[] encodedMessage) { }
        public byte[] Encode() => null;
    }

    public sealed class EnvelopedCms
    {
        public EnvelopedCms() { }
        public EnvelopedCms(ContentInfo contentInfo) { }
        public EnvelopedCms(ContentInfo contentInfo, AlgorithmIdentifier encryptionAlgorithm) { }
        public ContentInfo ContentInfo { get; }
        public AlgorithmIdentifier ContentEncryptionAlgorithm { get; }
        public void Encrypt(CmsRecipient recipient) { }
        public void Decrypt() { }
        public void Decode(byte[] encodedMessage) { }
        public byte[] Encode() => null;
    }

    public sealed class AlgorithmIdentifier
    {
        public AlgorithmIdentifier() { }
        public AlgorithmIdentifier(Oid oid) { }
        public AlgorithmIdentifier(Oid oid, int keyLength) { }
        public Oid Oid { get; set; }
        public int KeyLength { get; set; }
    }

    public sealed class Pkcs12Builder
    {
        public Pkcs12Builder() { }
        public void SealWithMac(string password, HashAlgorithmName hashAlgorithm, int iterationCount) { }
        public byte[] Encode() => null;
    }

    public sealed class Pkcs12Info
    {
        public static Pkcs12Info Decode(byte[] encodedBytes, out int bytesConsumed) { bytesConsumed = 0; return null; }
    }

    public sealed class Pkcs8PrivateKeyInfo
    {
        public static Pkcs8PrivateKeyInfo Create(AsymmetricAlgorithm privateKey) => null;
        public static Pkcs8PrivateKeyInfo Decode(byte[] source, out int bytesRead) { bytesRead = 0; return null; }
        public byte[] Encode() => null;
    }

    public sealed class Rfc3161TimestampRequest
    {
        public static Rfc3161TimestampRequest CreateFromHash(byte[] hash, HashAlgorithmName hashAlgorithm) => null;
        public static Rfc3161TimestampRequest CreateFromData(byte[] data, HashAlgorithmName hashAlgorithm) => null;
        public static Rfc3161TimestampRequest CreateFromSignerInfo(SignerInfo signerInfo, HashAlgorithmName hashAlgorithm) => null;
        public byte[] Encode() => null;
    }

    public sealed class SignerInfo { }
}

// =============================================================================
// System.Security.Cryptography — KMAC (.NET 9+, not in the net8.0 reference set)
// =============================================================================
namespace System.Security.Cryptography
{
    public class Kmac128 : System.IDisposable
    {
        public Kmac128(byte[] key, byte[] customizationString = null) { }
        public static byte[] HashData(byte[] key, byte[] source, int outputLength, byte[] customizationString = null) => null;
        public void AppendData(byte[] data) { }
        public byte[] GetCurrentHash(int outputLength) => null;
        public byte[] GetHashAndReset(int outputLength) => null;
        public void Dispose() { }
    }

    public class Kmac256 : System.IDisposable
    {
        public Kmac256(byte[] key, byte[] customizationString = null) { }
        public static byte[] HashData(byte[] key, byte[] source, int outputLength, byte[] customizationString = null) => null;
        public void AppendData(byte[] data) { }
        public byte[] GetCurrentHash(int outputLength) => null;
        public byte[] GetHashAndReset(int outputLength) => null;
        public void Dispose() { }
    }

    public class KmacXof128 : System.IDisposable
    {
        public KmacXof128(byte[] key, byte[] customizationString = null) { }
        public static byte[] HashData(byte[] key, byte[] source, int outputLength, byte[] customizationString = null) => null;
        public void AppendData(byte[] data) { }
        public byte[] GetCurrentHash(int outputLength) => null;
        public byte[] GetHashAndReset(int outputLength) => null;
        public void Dispose() { }
    }

    public class KmacXof256 : System.IDisposable
    {
        public KmacXof256(byte[] key, byte[] customizationString = null) { }
        public static byte[] HashData(byte[] key, byte[] source, int outputLength, byte[] customizationString = null) => null;
        public void AppendData(byte[] data) { }
        public byte[] GetCurrentHash(int outputLength) => null;
        public byte[] GetHashAndReset(int outputLength) => null;
        public void Dispose() { }
    }
}

// =============================================================================
// System.Security.Cryptography — MACTripleDES (not in the net8.0 reference set)
// =============================================================================
namespace System.Security.Cryptography
{
    public class MACTripleDES : KeyedHashAlgorithm
    {
        public MACTripleDES() { }
        public MACTripleDES(byte[] rgbKey) { }
        public CipherMode Mode { get; set; }
        public PaddingMode Padding { get; set; }

        protected override void HashCore(byte[] array, int ibStart, int cbSize) { }
        protected override byte[] HashFinal() => null;
        public override void Initialize() { }
    }
}

// =============================================================================
// Org.BouncyCastle — additional digests, engines and MACs
// =============================================================================
namespace Org.BouncyCastle.Crypto.Digests
{
    using Org.BouncyCastle.Crypto;

    public class DSTU7564Digest     : IDigest { public DSTU7564Digest(int bits) { } }
    public class Haraka256Digest    : IDigest { }
    public class Haraka512Digest    : IDigest { }
    public class Blake2bpDigest     : IDigest { public Blake2bpDigest(int size) { } }
    public class Blake2spDigest     : IDigest { public Blake2spDigest(int size) { } }
    public class Blake2xsDigest     : IDigest { public Blake2xsDigest(int size) { } }
    public class AsconDigest        : IDigest { }
    public class AsconXof           : IDigest { }
    public class PhotonBeetleDigest : IDigest { }
    public class SparkleDigest      : IDigest { }
    public class XoodyakDigest      : IDigest { }
    public class IsapDigest         : IDigest { }
}

namespace Org.BouncyCastle.Crypto.Engines
{
    using Org.BouncyCastle.Crypto;

    public class RijndaelEngine  : IBlockCipher { public RijndaelEngine() { } public RijndaelEngine(int blockBits) { } }
    public class DstU7624Engine  : IBlockCipher { public DstU7624Engine(int blockBits) { } }
    public class Rc532Engine     : IBlockCipher { }
    public class Rc564Engine     : IBlockCipher { }
    public class ShacalEngine    : IBlockCipher { }
    public class Shacal2Engine   : IBlockCipher { }
    public class LeaEngine       : IBlockCipher { }

    // Key wrapping
    public interface IWrapper { }
    public class AesWrapEngine       : IWrapper { }
    public class AesWrapPadEngine    : IWrapper { }
    public class DesEdeWrapEngine    : IWrapper { }
    public class Rc2WrapEngine       : IWrapper { }
    public class CamelliaWrapEngine  : IWrapper { }
    public class SeedWrapEngine      : IWrapper { }
    public class AriaWrapEngine      : IWrapper { }
    public class AriaWrapPadEngine   : IWrapper { }
    public class DstU7624WrapEngine  : IWrapper { public DstU7624WrapEngine(int blockBits) { } }
    public class Gost28147WrapEngine : IWrapper { }
    public class Rfc3394WrapEngine   : IWrapper { public Rfc3394WrapEngine(IBlockCipher engine) { } }
    public class Rfc5649WrapEngine   : IWrapper { public Rfc5649WrapEngine(IBlockCipher engine) { } }

    // NIST lightweight cryptography AEAD ciphers
    public class AsconEngine        : IAeadCipher { public AsconEngine(int parameters) { } }
    public class ElephantEngine     : IAeadCipher { public ElephantEngine(int parameters) { } }
    public class IsapEngine         : IAeadCipher { public IsapEngine(int parameters) { } }
    public class PhotonBeetleEngine : IAeadCipher { public PhotonBeetleEngine(int parameters) { } }
    public class SparkleEngine      : IAeadCipher { public SparkleEngine(int parameters) { } }
    public class XoodyakEngine      : IAeadCipher { public XoodyakEngine() { } }
    public class RomulusEngine      : IAeadCipher { public RomulusEngine(int parameters) { } }
    public class TinyJambuEngine    : IAeadCipher { public TinyJambuEngine(int parameters) { } }

    // Integrated encryption schemes
    public class IesEngine         { public IesEngine(IBasicAgreement agree, IDerivationFunction kdf, IMac mac) { } }
    public class EthereumIesEngine { public EthereumIesEngine(IBasicAgreement agree, IDerivationFunction kdf, IMac mac) { } }
}

namespace Org.BouncyCastle.Crypto.Macs
{
    using Org.BouncyCastle.Crypto;

    public class KMac          : IMac { public KMac(int bitLength, byte[] s) { } }
    public class TupleHash     : IMac { public TupleHash(int bitLength, byte[] s) { } }
    public class ParallelHash  : IMac { public ParallelHash(int bitLength, byte[] s, int b) { } }
    public class DSTU7564Mac   : IMac { public DSTU7564Mac(int macBits) { } }
    public class DSTU7624Mac   : IMac { public DSTU7624Mac(int blockBits, int macBits) { } }
    public class Gost28147Mac  : IMac { }
    public class SkeinMac      : IMac { public SkeinMac(int stateBits, int digestBits) { } }
    public class Blake3Mac     : IMac { public Blake3Mac(int bitLength) { } }
}

namespace Org.BouncyCastle.Crypto.Modes
{
    using Org.BouncyCastle.Crypto;

    public class GcmSivBlockCipher  : IAeadBlockCipher { public GcmSivBlockCipher(IBlockCipher c) { } }
    public class KCcmBlockCipher    : IAeadBlockCipher { public KCcmBlockCipher(IBlockCipher c) { } }
    public class KGcmBlockCipher    : IAeadBlockCipher { public KGcmBlockCipher(IBlockCipher c) { } }
    public class KXtsBlockCipher    : IBlockCipher     { public KXtsBlockCipher(IBlockCipher c) { } }
    public class XtsBlockCipher     : IBlockCipher     { public XtsBlockCipher(IBlockCipher c) { } }
    public class G3413CbcBlockCipher : IBlockCipher    { public G3413CbcBlockCipher(IBlockCipher c) { } }
    public class G3413CtrBlockCipher : IBlockCipher    { public G3413CtrBlockCipher(IBlockCipher c) { } }
}

namespace Org.BouncyCastle.Crypto.Paddings
{
    using Org.BouncyCastle.Crypto;

    public class ISO7816d4Padding : IBlockCipherPadding { }
    public class BufferedBlockCipher : IBufferedCipher
    {
        public BufferedBlockCipher(IBlockCipher cipher) { }
    }
}

namespace Org.BouncyCastle.Crypto.Generators
{
    using Org.BouncyCastle.Crypto;

    public class DsaParametersGenerator     { public void Init(int size, int certainty, Org.BouncyCastle.Security.SecureRandom random) { } }
    public class DHParametersGenerator      { public void Init(int size, int certainty, Org.BouncyCastle.Security.SecureRandom random) { } }
    public class ElGamalParametersGenerator { public void Init(int size, int certainty, Org.BouncyCastle.Security.SecureRandom random) { } }
}

namespace Org.BouncyCastle.Crypto.Agreement
{
    public class Sm2KeyExchange { }
}

// =============================================================================
// Org.BouncyCastle — named elliptic curve tables
// =============================================================================
namespace Org.BouncyCastle.Asn1.X9
{
    public class X962NamedCurves { public static X9ECParameters GetByName(string name) => null; }
}

namespace Org.BouncyCastle.Crypto.EC
{
    using Org.BouncyCastle.Asn1.X9;
    public class CustomNamedCurves { public static X9ECParameters GetByName(string name) => null; }
}

namespace Org.BouncyCastle.Asn1.Sec
{
    using Org.BouncyCastle.Asn1.X9;
    public class SecNamedCurves { public static X9ECParameters GetByName(string name) => null; }
}

namespace Org.BouncyCastle.Asn1.TeleTrust
{
    using Org.BouncyCastle.Asn1.X9;
    public class TeleTrusTNamedCurves { public static X9ECParameters GetByName(string name) => null; }
}

namespace Org.BouncyCastle.Asn1.Anssi
{
    using Org.BouncyCastle.Asn1.X9;
    public class AnssiNamedCurves { public static X9ECParameters GetByName(string name) => null; }
}

namespace Org.BouncyCastle.Asn1.GM
{
    using Org.BouncyCastle.Asn1.X9;
    public class GMNamedCurves { public static X9ECParameters GetByName(string name) => null; }
}

// =============================================================================
// Org.BouncyCastle.Pqc.Crypto — post-quantum algorithms
// =============================================================================
namespace Org.BouncyCastle.Pqc.Crypto
{
    public class MLKemGenerator          { public MLKemGenerator(Org.BouncyCastle.Security.SecureRandom random) { } }
    public class MLKemExtractor          { public MLKemExtractor(object privateKey) { } }
    public class MLKemKeyPairGenerator   { }
    public class KyberKemGenerator       { public KyberKemGenerator(Org.BouncyCastle.Security.SecureRandom random) { } }
    public class KyberKemExtractor       { public KyberKemExtractor(object privateKey) { } }
    public class KyberKeyPairGenerator   { }
    public class MLDsaSigner             { public MLDsaSigner() { } }
    public class MLDsaKeyPairGenerator   { }
    public class DilithiumSigner         { }
    public class DilithiumKeyPairGenerator { }
    public class SlhDsaSigner            { }
    public class SlhDsaKeyPairGenerator  { }
    public class SphincsPlusSigner       { }
    public class SphincsPlusKeyPairGenerator { }
    public class FalconSigner            { }
    public class FalconKeyPairGenerator  { }
    public class NtruKemGenerator        { public NtruKemGenerator(Org.BouncyCastle.Security.SecureRandom random) { } }
    public class NtruKeyPairGenerator    { }
    public class SntruPrimeKemGenerator  { public SntruPrimeKemGenerator(Org.BouncyCastle.Security.SecureRandom random) { } }
    public class FrodoKemGenerator       { public FrodoKemGenerator(Org.BouncyCastle.Security.SecureRandom random) { } }
    public class FrodoKeyPairGenerator   { }
    public class SaberKemGenerator       { public SaberKemGenerator(Org.BouncyCastle.Security.SecureRandom random) { } }
    public class BikeKemGenerator        { public BikeKemGenerator(Org.BouncyCastle.Security.SecureRandom random) { } }
    public class HqcKemGenerator         { public HqcKemGenerator(Org.BouncyCastle.Security.SecureRandom random) { } }
    public class CmceKemGenerator        { public CmceKemGenerator(Org.BouncyCastle.Security.SecureRandom random) { } }
    public class PicnicSigner            { }
    public class RainbowSigner           { }
    public class XmssSigner              { }
    public class XmssKeyPairGenerator    { }
    public class XmssMTSigner            { }
    public class LmsSigner               { }
    public class HssSigner               { }
    public class NHAgreement             { }
}

// =============================================================================
// Org.BouncyCastle — TLS, CMS and OpenPGP protocol layers
// =============================================================================
namespace Org.BouncyCastle.Tls
{
    public class TlsClientProtocol  { public TlsClientProtocol(System.IO.Stream stream) { } }
    public class TlsServerProtocol  { public TlsServerProtocol(System.IO.Stream stream) { } }
    public class DtlsClientProtocol { }
    public class DtlsServerProtocol { }
}

namespace Org.BouncyCastle.Cms
{
    public class CmsSignedDataGenerator    { }
    public class CmsEnvelopedDataGenerator { }
    public class CmsSignedData             { public CmsSignedData(byte[] encoded) { } }
    public class CmsEnvelopedData          { public CmsEnvelopedData(byte[] encoded) { } }
}

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpEncryptedDataGenerator { public PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag tag) { } }
    public class PgpSignatureGenerator     { public PgpSignatureGenerator(PublicKeyAlgorithmTag keyAlg, HashAlgorithmTag hashAlg) { } }
    public class PgpKeyRingGenerator       { }
    public class PgpKeyPair                { }
}

namespace Org.BouncyCastle.Security
{
    public class WrapperUtilities
    {
        public static object GetWrapper(string algorithm) => null;
    }
}

// =============================================================================
// Org.BouncyCastle.Bcpg — OpenPGP AEAD and modern public-key algorithm tags
// =============================================================================
namespace Org.BouncyCastle.Bcpg
{
    public enum AeadAlgorithmTag { Eax, Ocb, Gcm }
}

// =============================================================================
// Org.BouncyCastle.Crypto.Fpe — NIST SP 800-38G format-preserving encryption
// =============================================================================
namespace Org.BouncyCastle.Crypto.Fpe
{
    using Org.BouncyCastle.Crypto;

    public class FpeFf1Engine : IBlockCipher { public FpeFf1Engine(IBlockCipher cipher, int radix) { } }
    public class FpeFf3_1Engine : IBlockCipher { public FpeFf3_1Engine(IBlockCipher cipher, int radix) { } }
}

// =============================================================================
// Azure.Security.KeyVault.Keys — curve names, key sizes and encrypt parameters
// =============================================================================
namespace Azure.Security.KeyVault.Keys
{
    public struct KeyCurveName
    {
        public static readonly KeyCurveName P256  = default;
        public static readonly KeyCurveName P384  = default;
        public static readonly KeyCurveName P521  = default;
        public static readonly KeyCurveName P256K = default;
        public KeyCurveName(string value) { }
    }
}

namespace Azure.Security.KeyVault.Keys.Cryptography
{
    public class EncryptParameters
    {
        public static EncryptParameters Rsa15Parameters(byte[] plaintext) => null;
        public static EncryptParameters RsaOaepParameters(byte[] plaintext) => null;
        public static EncryptParameters RsaOaep256Parameters(byte[] plaintext) => null;
        public static EncryptParameters A128GcmParameters(byte[] plaintext, byte[] iv = null, byte[] aad = null) => null;
        public static EncryptParameters A192GcmParameters(byte[] plaintext, byte[] iv = null, byte[] aad = null) => null;
        public static EncryptParameters A256GcmParameters(byte[] plaintext, byte[] iv = null, byte[] aad = null) => null;
        public static EncryptParameters A128CbcParameters(byte[] plaintext, byte[] iv = null) => null;
        public static EncryptParameters A256CbcParameters(byte[] plaintext, byte[] iv = null) => null;
        public static EncryptParameters A128CbcPadParameters(byte[] plaintext, byte[] iv = null) => null;
        public static EncryptParameters A256CbcPadParameters(byte[] plaintext, byte[] iv = null) => null;
    }

    public class DecryptParameters
    {
        public static DecryptParameters Rsa15Parameters(byte[] ciphertext) => null;
        public static DecryptParameters RsaOaepParameters(byte[] ciphertext) => null;
        public static DecryptParameters RsaOaep256Parameters(byte[] ciphertext) => null;
        public static DecryptParameters A256GcmParameters(byte[] ciphertext, byte[] iv, byte[] authenticationTag, byte[] aad = null) => null;
        public static DecryptParameters A256CbcPadParameters(byte[] ciphertext, byte[] iv = null) => null;
    }
}

// =============================================================================
// Microsoft.Azure.KeyVault — legacy track-1 SDK
// =============================================================================
namespace Microsoft.Azure.KeyVault
{
    public class KeyVaultClient
    {
        public KeyVaultClient(object credentials) { }
        public System.Threading.Tasks.Task<object> EncryptAsync(string keyIdentifier, string algorithm, byte[] value) => null;
        public System.Threading.Tasks.Task<object> DecryptAsync(string keyIdentifier, string algorithm, byte[] value) => null;
        public System.Threading.Tasks.Task<object> SignAsync(string keyIdentifier, string algorithm, byte[] digest) => null;
        public System.Threading.Tasks.Task<object> VerifyAsync(string keyIdentifier, string algorithm, byte[] digest, byte[] signature) => null;
        public System.Threading.Tasks.Task<object> WrapKeyAsync(string keyIdentifier, string algorithm, byte[] key) => null;
        public System.Threading.Tasks.Task<object> UnwrapKeyAsync(string keyIdentifier, string algorithm, byte[] key) => null;
        public System.Threading.Tasks.Task<object> CreateKeyAsync(string vaultBaseUrl, string keyName, string keyType) => null;
        public System.Threading.Tasks.Task<object> GetSecretAsync(string secretIdentifier) => null;
    }
}

namespace Microsoft.Azure.KeyVault.WebKey
{
    public static class JsonWebKeyEncryptionAlgorithm
    {
        public const string RSAOAEP    = "RSA-OAEP";
        public const string RSAOAEP256 = "RSA-OAEP-256";
        public const string RSA15      = "RSA1_5";
    }
    public static class JsonWebKeySignatureAlgorithm
    {
        public const string RS256 = "RS256";
        public const string ES256 = "ES256";
        public const string PS256 = "PS256";
    }
    public static class JsonWebKeyCurveName
    {
        public const string P256 = "P-256";
        public const string P384 = "P-384";
    }
}

// =============================================================================
// Jose — settings and JWK types
// =============================================================================
namespace Jose
{
    public class JwtSettings
    {
        public JwtSettings RegisterJws(JwsAlgorithm alg, object impl) => this;
        public JwtSettings RegisterJwe(JweEncryption alg, object impl) => this;
        public JwtSettings RegisterJwa(JweAlgorithm alg, object impl) => this;
        public JwtSettings RegisterMapper(object mapper) => this;
        public JwtSettings RegisterJwsAlias(string alias, JwsAlgorithm alg) => this;
        public JwtSettings RegisterJweAlias(string alias, JweEncryption alg) => this;
        public JwtSettings RegisterJwaAlias(string alias, JweAlgorithm alg) => this;
        public JwtSettings DeregisterJws(JwsAlgorithm alg) => this;
        public JwtSettings DeregisterJwe(JweEncryption alg) => this;
        public JwtSettings DeregisterJwa(JweAlgorithm alg) => this;
    }

    public class Jwk
    {
        public Jwk(string kty) { }
        public Jwk(System.Security.Cryptography.RSA key, bool isPrivate = false) { }
        public static Jwk FromJson(string json, object mapper = null) => null;
    }

    public class JwkSet
    {
        public JwkSet() { }
        public static JwkSet FromJson(string json, object mapper = null) => null;
    }
}
