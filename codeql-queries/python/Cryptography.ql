/**
 * @name Crypto inventory — pyca/cryptography library (Python)
 * @description Inventory of pyca/cryptography library usage including hashes,
 *              ciphers, AEAD, KDFs, asymmetric primitives, X.509, and Fernet.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/python-cbom-cryptography
 * @tags security
 */

import python
import lib.PyCryptoCommon

from Call call, string algo, string api
where
  api = "cryptography" and
  (
    // =============================================================================
    // Hash Algorithms — hashes.SHA256(), hashes.MD5(), etc.
    // Matches: hashes.X() where object toString contains "hashes"
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%hashes%") and
        (
          (attr.getName() = "SHA1"      and algo = "sha1") or
          (attr.getName() = "SHA224"    and algo = "sha224") or
          (attr.getName() = "SHA256"    and algo = "sha256") or
          (attr.getName() = "SHA384"    and algo = "sha384") or
          (attr.getName() = "SHA512"    and algo = "sha512") or
          (attr.getName() = "SHA512_224" and algo = "sha512-224") or
          (attr.getName() = "SHA512_256" and algo = "sha512-256") or
          (attr.getName() = "SHA3_224"  and algo = "sha3-224") or
          (attr.getName() = "SHA3_256"  and algo = "sha3-256") or
          (attr.getName() = "SHA3_384"  and algo = "sha3-384") or
          (attr.getName() = "SHA3_512"  and algo = "sha3-512") or
          (attr.getName() = "SHAKE128"  and algo = "shake-128") or
          (attr.getName() = "SHAKE256"  and algo = "shake-256") or
          (attr.getName() = "MD5"       and algo = "md5") or
          (attr.getName() = "BLAKE2b"   and algo = "blake2b") or
          (attr.getName() = "BLAKE2s"   and algo = "blake2s") or
          (attr.getName() = "SM3"       and algo = "sm3")
        )
      )
    )

    or

    // Direct Name-based hash constructors (from ... import SHA256; SHA256())
    (
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "SHA256" and algo = "sha256") or
          (fn.getId() = "SHA384" and algo = "sha384") or
          (fn.getId() = "SHA512" and algo = "sha512") or
          (fn.getId() = "SHA1"   and algo = "sha1") or
          (fn.getId() = "MD5"    and algo = "md5")
        )
      ) and
      // Guard: only match if file has cryptography-related import
      fileImportsCryptography(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // Hash object creation — hashes.Hash(hashes.SHA256())
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%hashes%") and
        attr.getName() = "Hash"
      ) and
      (
        exists(string h | h = resolveHashAlgoEnhanced(call, "algorithm") |
          algo = "hash-" + h
        )
        or
        (
          not exists(resolveHashAlgoEnhanced(call, "algorithm")) and
          exists(string h | h = resolveHashAlgoPositionalEnhanced(call, 0) |
            algo = "hash-" + h
          )
        )
        or
        (
          not exists(resolveHashAlgoEnhanced(call, "algorithm")) and
          not exists(resolveHashAlgoPositionalEnhanced(call, 0)) and
          algo = "unresolved"
        )
      )
    )

    or

    // =============================================================================
    // AEAD Ciphers — one-shot high-level API
    // AESGCM(key), AESCCM(key), ChaCha20Poly1305(key), etc.
    // =============================================================================
    (
      isConstructorCall(call, "AESGCM") and algo = "aes-gcm"
    ) or
    (
      isConstructorCall(call, "AESCCM") and algo = "aes-ccm"
    ) or
    (
      isConstructorCall(call, "AESGCMSIV") and algo = "aes-gcm-siv"
    ) or
    (
      isConstructorCall(call, "AESSIV") and algo = "aes-siv"
    ) or
    (
      isConstructorCall(call, "AESOCB3") and algo = "aes-ocb3"
    ) or
    (
      isConstructorCall(call, "ChaCha20Poly1305") and algo = "chacha20-poly1305"
    )

    or

    // =============================================================================
    // Cipher — Cipher(algorithms.AES(key), modes.GCM(nonce))
    // =============================================================================
    (
      isConstructorCall(call, "Cipher") and
      (
        // Both algorithm and mode resolved (enhanced)
        exists(string algoName, string modeName |
          algoName = resolveHashAlgoPositionalEnhanced(call, 0) and
          modeName = resolveHashAlgoPositionalEnhanced(call, 1) and
          algo = algoName + "-" + modeName
        )
        or
        // Algorithm only (no mode or mode is None)
        (
          not exists(resolveHashAlgoPositionalEnhanced(call, 1)) and
          exists(string algoName | algoName = resolveHashAlgoPositionalEnhanced(call, 0) |
            algo = algoName
          )
        )
        or
        // Neither resolved — unresolved
        (
          not exists(resolveHashAlgoPositionalEnhanced(call, 0)) and
          not exists(getKeywordAttrCallName(call, "algorithm")) and
          not exists(getKeywordNameCallId(call, "algorithm")) and
          algo = "unresolved"
        )
      )
    )

    or

    // Also match Cipher via keyword arguments
    (
      isConstructorCall(call, "Cipher") and
      exists(string algoName |
        algoName = getKeywordAttrCallName(call, "algorithm").toLowerCase() or
        algoName = getKeywordNameCallId(call, "algorithm").toLowerCase()
      |
        exists(string modeName |
          modeName = getKeywordAttrCallName(call, "mode").toLowerCase() or
          modeName = getKeywordNameCallId(call, "mode").toLowerCase()
        |
          algo = algoName + "-" + modeName
        )
        or
        (
          not exists(getKeywordAttrCallName(call, "mode")) and
          not exists(getKeywordNameCallId(call, "mode")) and
          algo = algoName
        )
      )
    )

    or

    // =============================================================================
    // Cipher Encryptor/Decryptor — cipher.encryptor(), cipher.decryptor()
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "encryptor" and algo = "cipher-encryptor") or
          (attr.getName() = "decryptor" and algo = "cipher-decryptor")
        )
      ) and
      fileImportsCryptography(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // Cipher Algorithm Constructors — algorithms.AES(key), algorithms.TripleDES(key)
    // Detected independently when used outside Cipher() context.
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%algorithms%") and
        (
          (attr.getName() = "AES"        and algo = "cipher-algo-aes") or
          (attr.getName() = "AES128"     and algo = "cipher-algo-aes128") or
          (attr.getName() = "AES256"     and algo = "cipher-algo-aes256") or
          (attr.getName() = "TripleDES"  and algo = "cipher-algo-3des") or
          (attr.getName() = "Camellia"   and algo = "cipher-algo-camellia") or
          (attr.getName() = "CAST5"      and algo = "cipher-algo-cast5") or
          (attr.getName() = "SEED"       and algo = "cipher-algo-seed") or
          (attr.getName() = "SM4"        and algo = "cipher-algo-sm4") or
          (attr.getName() = "Blowfish"   and algo = "cipher-algo-blowfish") or
          (attr.getName() = "ARC4"       and algo = "cipher-algo-arc4") or
          (attr.getName() = "IDEA"       and algo = "cipher-algo-idea") or
          (attr.getName() = "ChaCha20"   and algo = "cipher-algo-chacha20")
        )
      )
    )

    or

    // =============================================================================
    // KDFs — PBKDF2HMAC, Scrypt, HKDF, HKDFExpand, X963KDF, ConcatKDF, KBKDF
    // =============================================================================

    // PBKDF2HMAC(algorithm=hashes.SHA256(), ...)
    (
      isConstructorCall(call, "PBKDF2HMAC") and
      (
        exists(string h | h = resolveHashAlgoEnhanced(call, "algorithm") |
          algo = "pbkdf2-hmac-" + h
        )
        or
        (
          not exists(resolveHashAlgoEnhanced(call, "algorithm")) and
          exists(string h | h = resolveHashAlgoPositionalEnhanced(call, 0) |
            algo = "pbkdf2-hmac-" + h
          )
        )
        or
        (
          not exists(resolveHashAlgoEnhanced(call, "algorithm")) and
          not exists(resolveHashAlgoPositionalEnhanced(call, 0)) and
          algo = "unresolved"
        )
      )
    )

    or

    // Scrypt(salt, length, n, r, p)
    (
      isConstructorCall(call, "Scrypt") and algo = "scrypt"
    )

    or

    // HKDF(algorithm=hashes.SHA256(), ...)
    (
      isConstructorCall(call, "HKDF") and
      (
        exists(string h | h = resolveHashAlgoEnhanced(call, "algorithm") |
          algo = "hkdf-" + h
        )
        or
        (not exists(resolveHashAlgoEnhanced(call, "algorithm")) and algo = "unresolved")
      )
    )

    or

    // HKDFExpand(algorithm=hashes.SHA256(), ...)
    (
      isConstructorCall(call, "HKDFExpand") and
      (
        exists(string h | h = resolveHashAlgoEnhanced(call, "algorithm") |
          algo = "hkdf-expand-" + h
        )
        or
        (not exists(resolveHashAlgoEnhanced(call, "algorithm")) and algo = "unresolved")
      )
    )

    or

    // X963KDF
    (isConstructorCall(call, "X963KDF") and algo = "x963kdf")

    or

    // ConcatKDFHash
    (isConstructorCall(call, "ConcatKDFHash") and algo = "concatkdf-hash")

    or

    // ConcatKDFHMAC
    (isConstructorCall(call, "ConcatKDFHMAC") and algo = "concatkdf-hmac")

    or

    // KBKDFHMAC
    (isConstructorCall(call, "KBKDFHMAC") and algo = "kbkdf-hmac")

    or

    // KBKDFCMAC
    (isConstructorCall(call, "KBKDFCMAC") and algo = "kbkdf-cmac")

    or

    // =============================================================================
    // Asymmetric — RSA Key Generation
    // rsa.generate_private_key(public_exponent=65537, key_size=2048)
    // =============================================================================
    (
      isAttrCall(call, "rsa", "generate_private_key") and
      algo = "rsa-keygen"
    )

    or

    // =============================================================================
    // Asymmetric — EC Key Generation
    // ec.generate_private_key(ec.SECP256R1())
    // =============================================================================
    (
      isAttrCall(call, "ec", "generate_private_key") and
      (
        exists(string curve | curve = resolveHashAlgoPositionalEnhanced(call, 0) |
          algo = "ec-keygen-" + curve
        )
        or
        (
          not exists(resolveHashAlgoPositionalEnhanced(call, 0)) and
          algo = "unresolved"
        )
      )
    )

    or

    // EC curve constructors: ec.SECP256R1(), ec.SECP384R1(), etc.
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%ec%") and
        (
          (attr.getName() = "SECP256R1" and algo = "ec-curve-secp256r1") or
          (attr.getName() = "SECP384R1" and algo = "ec-curve-secp384r1") or
          (attr.getName() = "SECP521R1" and algo = "ec-curve-secp521r1") or
          (attr.getName() = "SECP256K1" and algo = "ec-curve-secp256k1") or
          (attr.getName() = "BrainpoolP256R1" and algo = "ec-curve-brainpoolp256r1") or
          (attr.getName() = "BrainpoolP384R1" and algo = "ec-curve-brainpoolp384r1") or
          (attr.getName() = "BrainpoolP512R1" and algo = "ec-curve-brainpoolp512r1")
        )
      )
    )

    or

    // ECDH key exchange
    (isConstructorCall(call, "ECDH") and algo = "ecdh")

    or

    // =============================================================================
    // Asymmetric — Ed25519, Ed448, X25519, X448
    // =============================================================================
    (isClassMethodCall(call, "Ed25519PrivateKey", "generate") and algo = "ed25519-keygen") or
    (isClassMethodCall(call, "Ed25519PublicKey", "from_public_bytes") and algo = "ed25519-import") or
    (isClassMethodCall(call, "Ed448PrivateKey", "generate") and algo = "ed448-keygen") or
    (isClassMethodCall(call, "Ed448PublicKey", "from_public_bytes") and algo = "ed448-import") or
    (isClassMethodCall(call, "X25519PrivateKey", "generate") and algo = "x25519-keygen") or
    (isClassMethodCall(call, "X25519PublicKey", "from_public_bytes") and algo = "x25519-import") or
    (isClassMethodCall(call, "X448PrivateKey", "generate") and algo = "x448-keygen") or
    (isClassMethodCall(call, "X448PublicKey", "from_public_bytes") and algo = "x448-import")

    or

    // =============================================================================
    // Asymmetric — DSA
    // =============================================================================
    (isAttrCall(call, "dsa", "generate_private_key") and algo = "dsa-keygen") or
    (isAttrCall(call, "dsa", "generate_parameters") and algo = "dsa-params")

    or

    // =============================================================================
    // Asymmetric — DH (Diffie-Hellman)
    // =============================================================================
    (isAttrCall(call, "dh", "generate_parameters") and algo = "dh-params") or
    (isClassMethodCall(call, "DHPrivateKey", "generate") and algo = "dh-keygen")

    or

    // =============================================================================
    // RSA Padding — OAEP, PSS, PKCS1v15
    // =============================================================================
    (isConstructorCall(call, "OAEP") and algo = "rsa-padding-oaep") or
    (isConstructorCall(call, "PSS") and algo = "rsa-padding-pss") or
    (isConstructorCall(call, "PKCS1v15") and algo = "rsa-padding-pkcs1v15")

    or

    // Also match via padding.OAEP(), padding.PSS(), padding.PKCS1v15()
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%padding%") and
        (
          (attr.getName() = "OAEP"     and algo = "rsa-padding-oaep") or
          (attr.getName() = "PSS"      and algo = "rsa-padding-pss") or
          (attr.getName() = "PKCS1v15" and algo = "rsa-padding-pkcs1v15")
        )
      )
    )

    or

    // =============================================================================
    // X.509 Certificates
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%x509%") and
        (
          (attr.getName() = "load_pem_x509_certificate"    and algo = "x509-load-pem") or
          (attr.getName() = "load_der_x509_certificate"    and algo = "x509-load-der") or
          (attr.getName() = "load_pem_x509_crl"            and algo = "x509-load-crl-pem") or
          (attr.getName() = "load_der_x509_crl"            and algo = "x509-load-crl-der") or
          (attr.getName() = "load_pem_x509_csr"            and algo = "x509-load-csr-pem") or
          (attr.getName() = "load_der_x509_csr"            and algo = "x509-load-csr-der") or
          (attr.getName() = "CertificateBuilder"           and algo = "x509-builder") or
          (attr.getName() = "CertificateSigningRequestBuilder" and algo = "x509-csr-builder") or
          (attr.getName() = "CertificateRevocationListBuilder" and algo = "x509-crl-builder")
        )
      )
    )

    or

    // Direct Name constructors for X.509
    (isConstructorCall(call, "CertificateBuilder") and algo = "x509-builder") or
    (isConstructorCall(call, "CertificateSigningRequestBuilder") and algo = "x509-csr-builder")

    or

    // =============================================================================
    // Key Serialization — loading private/public keys
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%serialization%") and
        (
          (attr.getName() = "load_pem_private_key"  and algo = "key-load-pem-private") or
          (attr.getName() = "load_der_private_key"  and algo = "key-load-der-private") or
          (attr.getName() = "load_ssh_private_key"  and algo = "key-load-ssh-private") or
          (attr.getName() = "load_pem_public_key"   and algo = "key-load-pem-public") or
          (attr.getName() = "load_der_public_key"   and algo = "key-load-der-public") or
          (attr.getName() = "load_ssh_public_key"   and algo = "key-load-ssh-public") or
          (attr.getName() = "load_pem_parameters"   and algo = "key-load-pem-params")
        )
      )
    )

    or

    // Direct calls after import: load_pem_private_key(data, password)
    (
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "load_pem_private_key"  and algo = "key-load-pem-private") or
          (fn.getId() = "load_der_private_key"  and algo = "key-load-der-private") or
          (fn.getId() = "load_ssh_private_key"  and algo = "key-load-ssh-private") or
          (fn.getId() = "load_pem_public_key"   and algo = "key-load-pem-public") or
          (fn.getId() = "load_der_public_key"   and algo = "key-load-der-public") or
          (fn.getId() = "load_ssh_public_key"   and algo = "key-load-ssh-public")
        )
      )
    )

    or

    // =============================================================================
    // Fernet — high-level symmetric encryption
    // =============================================================================
    (isConstructorCall(call, "Fernet") and algo = "fernet") or
    (isConstructorCall(call, "MultiFernet") and algo = "multi-fernet") or
    (isClassMethodCall(call, "Fernet", "generate_key") and algo = "fernet-keygen")

    or

    // =============================================================================
    // CMAC
    // =============================================================================
    (isConstructorCall(call, "CMAC") and algo = "cmac")

    or

    // =============================================================================
    // Poly1305
    // =============================================================================
    (isConstructorCall(call, "Poly1305") and algo = "poly1305")

    or

    // =============================================================================
    // HMAC via cryptography library
    // cryptography.hazmat.primitives.hmac.HMAC(key, hashes.SHA256())
    // =============================================================================
    (
      isConstructorCall(call, "HMAC") and
      fileImportsCryptography(call.getLocation().getFile()) and
      // Guard: must have a hash algorithm argument
      (
        exists(string h | h = resolveHashAlgoEnhanced(call, "algorithm") |
          algo = "hmac-" + h
        )
        or
        (
          not exists(resolveHashAlgoEnhanced(call, "algorithm")) and
          exists(string h | h = resolveHashAlgoPositionalEnhanced(call, 1) |
            algo = "hmac-" + h
          )
        )
        or
        (
          not exists(resolveHashAlgoEnhanced(call, "algorithm")) and
          not exists(resolveHashAlgoPositionalEnhanced(call, 1)) and
          algo = "unresolved"
        )
      )
    )

    or

    // =============================================================================
    // Asymmetric key operations — private_key.sign(), public_key.verify()
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "sign" and
        (
          attr.getObject().toString().matches("%private%key%") or
          attr.getObject().toString().matches("%priv%key%") or
          attr.getObject().toString().matches("%sk%") or
          attr.getObject().toString().matches("%signing_key%")
        )
      ) and
      fileImportsCryptography(call.getLocation().getFile()) and
      algo = "asymmetric-sign"
    )

    or

    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "verify" and
        (
          attr.getObject().toString().matches("%public%key%") or
          attr.getObject().toString().matches("%pub%key%") or
          attr.getObject().toString().matches("%vk%") or
          attr.getObject().toString().matches("%verifying_key%")
        )
      ) and
      fileImportsCryptography(call.getLocation().getFile()) and
      algo = "asymmetric-verify"
    )

    or

    // =============================================================================
    // Asymmetric encryption — public_key.encrypt(), private_key.decrypt()
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "encrypt" and
        (
          attr.getObject().toString().matches("%public%key%") or
          attr.getObject().toString().matches("%pub%key%")
        )
      ) and
      fileImportsCryptography(call.getLocation().getFile()) and
      algo = "asymmetric-encrypt"
    )

    or

    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "decrypt" and
        (
          attr.getObject().toString().matches("%private%key%") or
          attr.getObject().toString().matches("%priv%key%")
        )
      ) and
      fileImportsCryptography(call.getLocation().getFile()) and
      algo = "asymmetric-decrypt"
    )

    or

    // =============================================================================
    // Key exchange — private_key.exchange()
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "exchange" and
        (
          attr.getObject().toString().matches("%private%key%") or
          attr.getObject().toString().matches("%priv%key%")
        )
      ) and
      fileImportsCryptography(call.getLocation().getFile()) and
      algo = "key-exchange"
    )

    or

    // =============================================================================
    // Key serialization — private_key.private_bytes(), public_key.public_bytes()
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "private_bytes" and algo = "key-serialize-private") or
          (attr.getName() = "public_bytes"  and algo = "key-serialize-public")
        )
      ) and
      fileImportsCryptography(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // OCSP — OCSPRequestBuilder, OCSPResponseBuilder
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%ocsp%") and
        (
          (attr.getName() = "OCSPRequestBuilder"  and algo = "ocsp-request-builder") or
          (attr.getName() = "OCSPResponseBuilder" and algo = "ocsp-response-builder")
        )
      )
    ) or
    (isConstructorCall(call, "OCSPRequestBuilder") and algo = "ocsp-request-builder") or
    (isConstructorCall(call, "OCSPResponseBuilder") and algo = "ocsp-response-builder")

    or

    // =============================================================================
    // MGF1 — padding.MGF1(hashes.SHA256())
    // =============================================================================
    (
      (
        isConstructorCall(call, "MGF1") or
        exists(Attribute attr |
          call.getFunc() = attr and
          attr.getObject().toString().matches("%padding%") and
          attr.getName() = "MGF1"
        )
      ) and
      algo = "mgf1"
    )

    or

    // =============================================================================
    // Cipher Mode Constructors — modes.CBC(iv), modes.GCM(nonce), etc.
    // Detected independently when used outside Cipher() context.
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%modes%") and
        (
          (attr.getName() = "CBC"  and algo = "cipher-mode-cbc") or
          (attr.getName() = "CTR"  and algo = "cipher-mode-ctr") or
          (attr.getName() = "GCM"  and algo = "cipher-mode-gcm") or
          (attr.getName() = "ECB"  and algo = "cipher-mode-ecb") or
          (attr.getName() = "OFB"  and algo = "cipher-mode-ofb") or
          (attr.getName() = "CFB"  and algo = "cipher-mode-cfb") or
          (attr.getName() = "CFB8" and algo = "cipher-mode-cfb8") or
          (attr.getName() = "XTS"  and algo = "cipher-mode-xts")
        )
      )
    )

    or

    // =============================================================================
    // PKCS7 — pkcs7.PKCS7SignatureBuilder, pkcs7.serialize_certificates
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%pkcs7%") and
        (
          (attr.getName() = "PKCS7SignatureBuilder" and algo = "pkcs7-signature-builder") or
          (attr.getName() = "serialize_certificates" and algo = "pkcs7-serialize-certs")
        )
      )
    ) or
    (isConstructorCall(call, "PKCS7SignatureBuilder") and algo = "pkcs7-signature-builder")

    or

    // =============================================================================
    // EC derive_private_key — ec.derive_private_key(private_value, curve)
    // =============================================================================
    (
      isAttrCall(call, "ec", "derive_private_key") and algo = "ec-derive-private-key"
    )

    or

    // =============================================================================
    // Additional EC Curves
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%ec%") and
        (
          (attr.getName() = "SECP192R1" and algo = "ec-curve-secp192r1") or
          (attr.getName() = "SECP224R1" and algo = "ec-curve-secp224r1")
        )
      )
    )

    or

    // =============================================================================
    // Prehashed — utils.Prehashed(algorithm)
    // =============================================================================
    (
      (
        isConstructorCall(call, "Prehashed") or
        exists(Attribute attr |
          call.getFunc() = attr and
          attr.getObject().toString().matches("%utils%") and
          attr.getName() = "Prehashed"
        )
      ) and
      algo = "prehashed"
    )

    or

    // =============================================================================
    // KDF derive/verify methods — kdf.derive(key_material), kdf.verify(key, material)
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "derive" and algo = "kdf-derive") or
          (attr.getName() = "verify" and algo = "kdf-verify")
        ) and
        (
          attr.getObject().toString().matches("%kdf%") or
          attr.getObject().toString().matches("%pbkdf%") or
          attr.getObject().toString().matches("%hkdf%") or
          attr.getObject().toString().matches("%scrypt%")
        )
      ) and
      fileImportsCryptography(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // X.509 RevokedCertificateBuilder, OCSPRequest/Response load
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%x509%") and
        (
          (attr.getName() = "RevokedCertificateBuilder" and algo = "x509-revoked-builder") or
          (attr.getName() = "random_serial_number"      and algo = "x509-random-serial")
        )
      )
    ) or
    (isConstructorCall(call, "RevokedCertificateBuilder") and algo = "x509-revoked-builder")

    or

    // =============================================================================
    // OCSP load operations
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%ocsp%") and
        (
          (attr.getName() = "load_der_ocsp_request"   and algo = "ocsp-load-request") or
          (attr.getName() = "load_der_ocsp_response"  and algo = "ocsp-load-response")
        )
      )
    )

    or

    // =============================================================================
    // PKCS12 — pkcs12.load_key_and_certificates, pkcs12.serialize_key_and_certificates
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%pkcs12%") and
        (
          (attr.getName() = "load_key_and_certificates"       and algo = "pkcs12-load") or
          (attr.getName() = "load_pkcs12"                     and algo = "pkcs12-load") or
          (attr.getName() = "serialize_key_and_certificates"  and algo = "pkcs12-serialize")
        )
      )
    ) or
    (
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "load_key_and_certificates"      and algo = "pkcs12-load") or
          (fn.getId() = "load_pkcs12"                    and algo = "pkcs12-load") or
          (fn.getId() = "serialize_key_and_certificates" and algo = "pkcs12-serialize")
        )
      ) and
      fileImportsCryptography(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // Key serialization encoding/format constructors
    // serialization.BestAvailableEncryption(password)
    // serialization.NoEncryption()
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%serialization%") and
        (
          (attr.getName() = "BestAvailableEncryption" and algo = "key-encryption-best") or
          (attr.getName() = "NoEncryption"            and algo = "key-encryption-none")
        )
      )
    ) or
    (isConstructorCall(call, "BestAvailableEncryption") and algo = "key-encryption-best") or
    (isConstructorCall(call, "NoEncryption") and algo = "key-encryption-none")

    or

    // =============================================================================
    // AEAD generate_key() class methods
    // AESGCM.generate_key(256), AESCCM.generate_key(128), ChaCha20Poly1305.generate_key()
    // =============================================================================
    (isClassMethodCall(call, "AESGCM", "generate_key") and algo = "aes-gcm-keygen") or
    (isClassMethodCall(call, "AESCCM", "generate_key") and algo = "aes-ccm-keygen") or
    (isClassMethodCall(call, "ChaCha20Poly1305", "generate_key") and algo = "chacha20-poly1305-keygen") or
    (isClassMethodCall(call, "AESGCMSIV", "generate_key") and algo = "aes-gcm-siv-keygen") or
    (isClassMethodCall(call, "AESSIV", "generate_key") and algo = "aes-siv-keygen") or
    (isClassMethodCall(call, "AESOCB3", "generate_key") and algo = "aes-ocb3-keygen")

    or

    // =============================================================================
    // Ed25519/Ed448/X25519/X448 — from_private_bytes (key import)
    // =============================================================================
    (isClassMethodCall(call, "Ed25519PrivateKey", "from_private_bytes") and algo = "ed25519-import-private") or
    (isClassMethodCall(call, "Ed448PrivateKey", "from_private_bytes") and algo = "ed448-import-private") or
    (isClassMethodCall(call, "X25519PrivateKey", "from_private_bytes") and algo = "x25519-import-private") or
    (isClassMethodCall(call, "X448PrivateKey", "from_private_bytes") and algo = "x448-import-private")

    or

    // =============================================================================
    // ec.ECDSA — signature algorithm constructor
    // ec.ECDSA(hashes.SHA256())
    // =============================================================================
    (
      (
        isConstructorCall(call, "ECDSA") or
        exists(Attribute attr |
          call.getFunc() = attr and
          attr.getObject().toString().matches("%ec%") and
          attr.getName() = "ECDSA"
        )
      ) and
      fileImportsCryptography(call.getLocation().getFile()) and
      algo = "ecdsa"
    )

    or

    // =============================================================================
    // HOTP/TOTP — cryptography.hazmat.primitives.twofactor
    // =============================================================================
    (
      isConstructorCall(call, "HOTP") and
      fileImportsCryptography(call.getLocation().getFile()) and
      algo = "hotp"
    ) or
    (
      isConstructorCall(call, "TOTP") and
      fileImportsCryptography(call.getLocation().getFile()) and
      algo = "totp"
    )

    or

    // =============================================================================
    // RSA key construction from numbers
    // rsa.RSAPublicNumbers(e, n), rsa.RSAPrivateNumbers(p, q, d, ...)
    // =============================================================================
    (
      (
        isConstructorCall(call, "RSAPublicNumbers") or
        exists(Attribute attr |
          call.getFunc() = attr and
          attr.getObject().toString().matches("%rsa%") and
          attr.getName() = "RSAPublicNumbers"
        )
      ) and
      algo = "rsa-public-numbers"
    ) or
    (
      (
        isConstructorCall(call, "RSAPrivateNumbers") or
        exists(Attribute attr |
          call.getFunc() = attr and
          attr.getObject().toString().matches("%rsa%") and
          attr.getName() = "RSAPrivateNumbers"
        )
      ) and
      algo = "rsa-private-numbers"
    )

    or

    // =============================================================================
    // Key wrapping — aes_key_wrap, aes_key_unwrap (with/without padding)
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%keywrap%") and
        (
          (attr.getName() = "aes_key_wrap"                and algo = "aes-key-wrap") or
          (attr.getName() = "aes_key_unwrap"              and algo = "aes-key-unwrap") or
          (attr.getName() = "aes_key_wrap_with_padding"   and algo = "aes-key-wrap-pad") or
          (attr.getName() = "aes_key_unwrap_with_padding" and algo = "aes-key-unwrap-pad")
        )
      )
    ) or
    (
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "aes_key_wrap"                and algo = "aes-key-wrap") or
          (fn.getId() = "aes_key_unwrap"              and algo = "aes-key-unwrap") or
          (fn.getId() = "aes_key_wrap_with_padding"   and algo = "aes-key-wrap-pad") or
          (fn.getId() = "aes_key_unwrap_with_padding" and algo = "aes-key-unwrap-pad")
        )
      ) and
      fileImportsCryptography(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // x509.load_pem_x509_certificates (plural — PEM bundle loading)
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%x509%") and
        attr.getName() = "load_pem_x509_certificates"
      ) and
      algo = "x509-load-pem-bundle"
    )

    or

    // =============================================================================
    // serialization.load_der_parameters
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%serialization%") and
        attr.getName() = "load_der_parameters"
      ) and
      algo = "key-load-der-params"
    ) or
    (
      exists(Name fn |
        call.getFunc() = fn and
        fn.getId() = "load_der_parameters"
      ) and
      fileImportsCryptography(call.getLocation().getFile()) and
      algo = "key-load-der-params"
    )
  )
select call, "algo=" + algo + ", api=" + api
