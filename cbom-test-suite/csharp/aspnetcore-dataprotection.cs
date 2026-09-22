// Test suite for AspNetCoreDataProtection.ql
// Every method exercises at least one detection path in the QL query.
// The project is not intended to compile end-to-end; it exists so the
// CodeQL extractor (--build-mode=none + dotnet restore) can resolve types
// and produce ObjectCreation / MethodCall nodes for each predicate.

using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;

namespace CbomTestSuite.Csharp
{
    // =========================================================================
    // Core protect / unprotect operations
    // Expected algo tags: aspnetcore-dp-protect, aspnetcore-dp-unprotect
    // =========================================================================
    public static class DataProtectionCoreTests
    {
        private static readonly byte[] Data = new byte[64];

        public static byte[] ProtectBytes(IDataProtector protector)
            => protector.Protect(Data);

        public static byte[] UnprotectBytes(IDataProtector protector, byte[] ciphertext)
            => protector.Unprotect(ciphertext);

        // String extension overloads via DataProtectionCommonExtensions
        public static string ProtectString(IDataProtector protector)
            => DataProtectionCommonExtensions.Protect(protector, "plaintext");

        public static string UnprotectString(IDataProtector protector, string ciphertext)
            => DataProtectionCommonExtensions.Unprotect(protector, ciphertext);
    }

    // =========================================================================
    // Time-limited protection
    // Expected algo tags: aspnetcore-dp-timelimited-protect,
    //                     aspnetcore-dp-timelimited-unprotect,
    //                     aspnetcore-dp-timelimited
    // =========================================================================
    public static class TimeLimitedTests
    {
        private static readonly byte[] Data = new byte[64];

        public static byte[] ProtectWithExpiry(ITimeLimitedDataProtector protector)
            => protector.Protect(Data, DateTimeOffset.UtcNow.AddHours(1));

        public static byte[] UnprotectWithExpiry(ITimeLimitedDataProtector protector, byte[] ct)
        {
            DateTimeOffset expiry;
            return protector.Unprotect(ct, out expiry);
        }

        public static ITimeLimitedDataProtector WrapAsTimeLimited(IDataProtector protector)
            => protector.ToTimeLimitedDataProtector();
    }

    // =========================================================================
    // Provider and protector creation
    // Expected algo tags: aspnetcore-dp-provider, aspnetcore-dp-ephemeral-provider,
    //                     aspnetcore-dp-create-protector
    // =========================================================================
    public static class ProviderTests
    {
        public static IDataProtector FileSystemProvider()
        {
            var provider = new DataProtectionProvider(new DirectoryInfo("/tmp/keys"));
            return provider.CreateProtector("MyApp.Purpose");
        }

        public static IDataProtector EphemeralProvider()
        {
            var provider = new EphemeralDataProtectionProvider();
            return provider.CreateProtector("MyApp.Purpose");
        }

        public static IDataProtector ScopedProtector(IDataProtectionProvider provider)
            => DataProtectionCommonExtensions.CreateProtector(provider, "MyApp", "SubPurpose");
    }

    // =========================================================================
    // Low-level authenticated encryption (IAuthenticatedEncryptor)
    // Expected algo tags: aspnetcore-dp-auth-encrypt, aspnetcore-dp-auth-decrypt
    // =========================================================================
    public static class AuthEncryptorTests
    {
        private static readonly byte[] Data = new byte[64];
        private static readonly byte[] Aad = Array.Empty<byte>();

        public static byte[] Encrypt(IAuthenticatedEncryptor encryptor)
            => encryptor.Encrypt(new ArraySegment<byte>(Data), new ArraySegment<byte>(Aad));

        public static byte[] Decrypt(IAuthenticatedEncryptor encryptor, byte[] ciphertext)
            => encryptor.Decrypt(new ArraySegment<byte>(ciphertext), new ArraySegment<byte>(Aad));
    }

    // =========================================================================
    // Key management
    // Expected algo tags: aspnetcore-dp-key-create, aspnetcore-dp-key-revoke,
    //                     aspnetcore-dp-key-revoke-all, aspnetcore-dp-key-list,
    //                     aspnetcore-dp-key-manager
    // =========================================================================
    public static class KeyManagementTests
    {
        public static void CreateAndRevokeKeys(IKeyManager keyManager)
        {
            keyManager.CreateNewKey(
                activationDate: DateTimeOffset.UtcNow,
                expirationDate: DateTimeOffset.UtcNow.AddDays(90));

            keyManager.GetAllKeys();

            keyManager.RevokeKey(Guid.NewGuid(), reason: "Compromised");

            keyManager.RevokeAllKeys(
                revocationDate: DateTimeOffset.UtcNow,
                reason: "Key ring reset");
        }

        public static XmlKeyManager CreateXmlKeyManager(IServiceProvider services)
            => new XmlKeyManager(
                Microsoft.Extensions.Options.Options.Create(new KeyManagementOptions()),
                Microsoft.AspNetCore.DataProtection.Internal.IActivator.Instance,
                Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);
    }

    // =========================================================================
    // Algorithm configuration — EncryptionAlgorithm / ValidationAlgorithm enums
    //                         and algorithm config objects
    // Expected algo tags: aspnetcore-dp-encryptor-config,
    //   aes-128-cbc, aes-192-cbc, aes-256-cbc,
    //   aes-128-gcm, aes-192-gcm, aes-256-gcm,
    //   hmac-sha256, hmac-sha512,
    //   aspnetcore-dp-managed-encryptor-config,
    //   aspnetcore-dp-cng-cbc-config, aspnetcore-dp-cng-gcm-config
    // =========================================================================
    public static class AlgorithmConfigTests
    {
        public static AuthenticatedEncryptorConfiguration ConfigCbcHmac256()
            => new AuthenticatedEncryptorConfiguration
            {
                EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC,
                ValidationAlgorithm = ValidationAlgorithm.HMACSHA256
            };

        public static AuthenticatedEncryptorConfiguration ConfigGcm256Hmac512()
            => new AuthenticatedEncryptorConfiguration
            {
                EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM,
                ValidationAlgorithm = ValidationAlgorithm.HMACSHA512
            };

        public static void AllEncryptionAlgorithmEnumMembers()
        {
            _ = EncryptionAlgorithm.AES_128_CBC;
            _ = EncryptionAlgorithm.AES_192_CBC;
            _ = EncryptionAlgorithm.AES_256_CBC;
            _ = EncryptionAlgorithm.AES_128_GCM;
            _ = EncryptionAlgorithm.AES_192_GCM;
            _ = EncryptionAlgorithm.AES_256_GCM;
            _ = ValidationAlgorithm.HMACSHA256;
            _ = ValidationAlgorithm.HMACSHA512;
        }

        public static ManagedAuthenticatedEncryptorConfiguration ConfigManaged()
            => new ManagedAuthenticatedEncryptorConfiguration
            {
                EncryptionAlgorithmType = typeof(System.Security.Cryptography.Aes),
                EncryptionAlgorithmKeySize = 256,
                ValidationAlgorithmType = typeof(System.Security.Cryptography.HMACSHA256)
            };

        public static CngCbcAuthenticatedEncryptorConfiguration ConfigCngCbc()
            => new CngCbcAuthenticatedEncryptorConfiguration
            {
                EncryptionAlgorithm = "AES",
                EncryptionAlgorithmKeySize = 256,
                HashAlgorithm = "SHA256"
            };

        public static CngGcmAuthenticatedEncryptorConfiguration ConfigCngGcm()
            => new CngGcmAuthenticatedEncryptorConfiguration
            {
                EncryptionAlgorithm = "AES",
                EncryptionAlgorithmKeySize = 256
            };
    }

    // =========================================================================
    // XML key encryption providers
    // Expected algo tags: aspnetcore-dp-cert-xml-encryptor,
    //                     aspnetcore-dp-dpapi-xml-encryptor,
    //                     aspnetcore-dp-dpapi-ng-xml-encryptor,
    //                     aspnetcore-dp-xml-encrypt, aspnetcore-dp-xml-decrypt
    // =========================================================================
    public static class XmlKeyEncryptionTests
    {
        public static CertificateXmlEncryptor UseCertificateEncryptor(IServiceProvider services)
        {
            var cert = new X509Certificate2("cert.pfx", "password");
            return new CertificateXmlEncryptor(cert, services);
        }

#pragma warning disable CA1416
        public static DpapiXmlEncryptor UseDpapiEncryptor(IServiceProvider services)
            => new DpapiXmlEncryptor(protectToLocalMachine: true, services);

        public static DpapiNGXmlEncryptor UseDpapiNgEncryptor(IServiceProvider services)
            => new DpapiNGXmlEncryptor(
                "LOCAL=user",
                DpapiNGProtectionDescriptorFlags.None,
                services);
#pragma warning restore CA1416

        public static System.Xml.Linq.XElement EncryptXml(IXmlEncryptor encryptor, System.Xml.Linq.XElement element)
            => encryptor.Encrypt(element).EncryptedElement;

        public static System.Xml.Linq.XElement DecryptXml(IXmlDecryptor decryptor, System.Xml.Linq.XElement element)
            => decryptor.Decrypt(element);
    }

    // =========================================================================
    // Service registration and fluent builder configuration
    // Expected algo tags: aspnetcore-dp-configure, aspnetcore-dp-app-scope,
    //   aspnetcore-dp-key-lifetime, aspnetcore-dp-key-persist-filesystem,
    //   aspnetcore-dp-key-protect-certificate, aspnetcore-dp-key-protect-dpapi,
    //   aspnetcore-dp-key-protect-dpapi-ng, aspnetcore-dp-key-no-autogen,
    //   aspnetcore-dp-ephemeral, aspnetcore-dp-key-persist-azure-blob,
    //   aspnetcore-dp-key-protect-azure-key-vault,
    //   aspnetcore-dp-key-persist-ef-core, aspnetcore-dp-key-persist-redis,
    //   aspnetcore-dp-key-persist-registry
    // =========================================================================

    public static class ServiceRegistrationTests
    {
        public static IServiceCollection ConfigureStandard(IServiceCollection services)
        {
            services
                .AddDataProtection()
                .SetApplicationName("MyApp")
                .SetDefaultKeyLifetime(TimeSpan.FromDays(14))
                .PersistKeysToFileSystem(new DirectoryInfo("/var/keys"))
                .ProtectKeysWithCertificate(new X509Certificate2("cert.pfx"))
                .DisableAutomaticKeyGeneration();

            return services;
        }

#pragma warning disable CA1416
        public static IServiceCollection ConfigureWindowsDpapi(IServiceCollection services)
        {
            services
                .AddDataProtection()
                .ProtectKeysWithDpapi(protectToLocalMachine: false)
                .ProtectKeysWithDpapiNG();

            return services;
        }
#pragma warning restore CA1416

        public static IServiceCollection ConfigureEphemeral(IServiceCollection services)
        {
            services
                .AddDataProtection()
                .UseEphemeralDataProtectionProvider();

            return services;
        }

        // Cloud providers (require additional NuGet packages; included for
        // detection coverage — method names are matched by the QL query).
        public static void ConfigureCloud(IServiceCollection services)
        {
            services
                .AddDataProtection()
                .PersistKeysToAzureBlobStorage(new Uri("https://storage.blob.core.windows.net/keys/keys.xml"))
                .ProtectKeysWithAzureKeyVault(new Uri("https://vault.azure.net/keys/mykey"), null);
        }

        // Additional storage providers — method names matched by the QL query.
        public static void ConfigureAdditionalStorage(IServiceCollection services)
        {
            services.AddDataProtection().PersistKeysToDbContext<object>();
            services.AddDataProtection().PersistKeysToStackExchangeRedis(null, "DataProtection-Keys");
            services.AddDataProtection().PersistKeysToRegistry(null);
        }
    }

    // =========================================================================
    // Concrete algorithm selection via the fluent builder and configuration
    // objects. This is where the actual primitives are chosen.
    // Expected algo tags: aspnetcore-dp-algorithms, aspnetcore-dp-custom-algorithms,
    //                     aes-256-cbc, hmac-sha256, aes, hmacsha256,
    //                     aspnetcore-dp-keysize-256, sha256
    // =========================================================================
    public static class DpAlgorithmSelectionTests
    {
        public static void ConfigureBuiltInAlgorithms(IServiceCollection services)
        {
            services.AddDataProtection()
                    .UseCryptographicAlgorithms(new AuthenticatedEncryptorConfiguration
                    {
                        EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC,
                        ValidationAlgorithm = ValidationAlgorithm.HMACSHA256
                    });
        }

        public static void ConfigureManagedAlgorithms(IServiceCollection services)
        {
            services.AddDataProtection()
                    .UseCustomCryptographicAlgorithms(new ManagedAuthenticatedEncryptorConfiguration
                    {
                        EncryptionAlgorithmType = typeof(System.Security.Cryptography.Aes),
                        EncryptionAlgorithmKeySize = 256,
                        ValidationAlgorithmType = typeof(System.Security.Cryptography.HMACSHA256)
                    });
        }

        public static void ConfigureCngCbcAlgorithms(IServiceCollection services)
        {
            services.AddDataProtection()
                    .UseCustomCryptographicAlgorithms(new CngCbcAuthenticatedEncryptorConfiguration
                    {
                        EncryptionAlgorithm = "AES",
                        EncryptionAlgorithmKeySize = 256,
                        HashAlgorithm = "SHA256"
                    });
        }

        public static CngGcmAuthenticatedEncryptorConfiguration ConfigureCngGcmViaProperties()
        {
            var configuration = new CngGcmAuthenticatedEncryptorConfiguration();
            configuration.EncryptionAlgorithm = "AES";
            configuration.EncryptionAlgorithmKeySize = 192;
            return configuration;
        }
    }

    // =========================================================================
    // CNG provider selection and validation key size
    // Expected algo tags: aspnetcore-dp-cng-provider:*, aspnetcore-dp-keysize-*
    // =========================================================================
    public static class DpCngProviderTests
    {
        public static CngCbcAuthenticatedEncryptorConfiguration ExplicitProviders() =>
            new CngCbcAuthenticatedEncryptorConfiguration
            {
                EncryptionAlgorithm = "AES",
                EncryptionAlgorithmProvider = "Microsoft Primitive Provider",
                HashAlgorithm = "SHA512",
                HashAlgorithmProvider = "Microsoft Primitive Provider"
            };

        public static ManagedAuthenticatedEncryptorConfiguration ValidationKeySize() =>
            new ManagedAuthenticatedEncryptorConfiguration
            {
                EncryptionAlgorithmType = typeof(System.Security.Cryptography.Aes),
                ValidationAlgorithmType = typeof(System.Security.Cryptography.HMACSHA512),
                ValidationAlgorithmKeySize = 512
            };
    }

    // =========================================================================
    // Remaining key-ring persistence backends
    // Expected algo tags: aspnetcore-dp-key-persist-ef-core,
    //                     aspnetcore-dp-key-persist-redis,
    //                     aspnetcore-dp-key-persist-registry
    // =========================================================================
    public static class DpRemainingPersistenceTests
    {
        public static void PersistToEfCore(IServiceCollection services) =>
            services.AddDataProtection().PersistKeysToDbContext<object>();

        public static void PersistToRedis(IServiceCollection services, object multiplexer) =>
            services.AddDataProtection().PersistKeysToStackExchangeRedis(multiplexer, "DataProtection-Keys");

        public static void PersistToRegistry(IServiceCollection services, object registryKey) =>
            services.AddDataProtection().PersistKeysToRegistry(registryKey);
    }

}
