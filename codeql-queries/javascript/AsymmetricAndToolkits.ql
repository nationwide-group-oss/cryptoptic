/**
 * @name Crypto inventory — EC, Asymmetric & Crypto Toolkits (JavaScript/TypeScript)
 * @description Inventory of elliptic curve, NaCl, and full crypto toolkit library usage.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/javascript-cbom-asymmetric-toolkits
 * @tags security
 */

import javascript
import lib.CryptoCommon

from InvokeExpr call, string algo, string api
where
  (
    // =============================================================================
    // elliptic (~10M/wk) — new EC('secp256k1'), new EdDSA('ed25519')
    // =============================================================================

    // EC constructor: new EC('secp256k1') or new elliptic.ec('secp256k1')
    (
      api = "elliptic" and
      call instanceof NewExpr and
      (
        isModuleConstructorCall(call, "elliptic", "ec") or
        call.(NewExpr).getCalleeName() = "EC"
      ) and
      call.getNumArgument() >= 1 and
      algo = "ec-" + call.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )

    or

    // EdDSA constructor: new EdDSA('ed25519')
    (
      api = "elliptic" and
      call instanceof NewExpr and
      (
        isModuleConstructorCall(call, "elliptic", "eddsa") or
        call.(NewExpr).getCalleeName() = "EdDSA"
      ) and
      call.getNumArgument() >= 1 and
      algo = "eddsa-" + call.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )

    or

    // EC method calls — genKeyPair, keyFromPrivate, keyFromPublic, sign, verify
    (
      api = "elliptic" and
      call.getCalleeName() = ["genKeyPair", "keyFromPrivate", "keyFromPublic"] and
      // These are called on an EC instance — heuristic: check for chained usage
      // The algo is determined by the constructor, not here, but we flag the operation
      algo = "ec-operation"
    )

    or

    // =============================================================================
    // @noble/curves (~4M/wk) — named imports, method calls
    // =============================================================================

    // secp256k1
    (isNamedImportCall(call, "@noble/curves/secp256k1", "sign") and algo = "ecdsa-secp256k1" and api = "@noble/curves") or
    (isNamedImportCall(call, "@noble/curves/secp256k1", "verify") and algo = "ecdsa-secp256k1-verify" and api = "@noble/curves") or
    (isNamedImportCall(call, "@noble/curves/secp256k1", "getPublicKey") and algo = "ec-secp256k1-pubkey" and api = "@noble/curves") or
    (isNamedImportCall(call, "@noble/curves/secp256k1", "getSharedSecret") and algo = "ecdh-secp256k1" and api = "@noble/curves") or

    // Also catch via module member: import { secp256k1 } from '@noble/curves/secp256k1'
    // then secp256k1.sign(), secp256k1.verify(), etc.
    (
      api = "@noble/curves" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleMember("@noble/curves/secp256k1", "secp256k1") |
        (call = mod.getAMemberCall("sign").asExpr() and algo = "ecdsa-secp256k1") or
        (call = mod.getAMemberCall("verify").asExpr() and algo = "ecdsa-secp256k1-verify") or
        (call = mod.getAMemberCall("getPublicKey").asExpr() and algo = "ec-secp256k1-pubkey") or
        (call = mod.getAMemberCall("getSharedSecret").asExpr() and algo = "ecdh-secp256k1")
      )
    )

    or

    // ed25519
    (
      api = "@noble/curves" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleMember("@noble/curves/ed25519", "ed25519") |
        (call = mod.getAMemberCall("sign").asExpr() and algo = "eddsa-ed25519") or
        (call = mod.getAMemberCall("verify").asExpr() and algo = "eddsa-ed25519-verify") or
        (call = mod.getAMemberCall("getPublicKey").asExpr() and algo = "ed25519-pubkey")
      )
    )

    or

    // x25519
    (
      api = "@noble/curves" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleMember("@noble/curves/ed25519", "x25519") |
        (call = mod.getAMemberCall("getPublicKey").asExpr() and algo = "x25519-pubkey") or
        (call = mod.getAMemberCall("getSharedSecret").asExpr() and algo = "ecdh-x25519")
      )
    )

    or

    // ed448
    (
      api = "@noble/curves" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleMember("@noble/curves/ed448", "ed448") |
        (call = mod.getAMemberCall("sign").asExpr() and algo = "eddsa-ed448") or
        (call = mod.getAMemberCall("verify").asExpr() and algo = "eddsa-ed448-verify") or
        (call = mod.getAMemberCall("getPublicKey").asExpr() and algo = "ed448-pubkey")
      )
    )

    or

    // NIST curves (p256, p384, p521)
    (
      api = "@noble/curves" and
      exists(DataFlow::SourceNode mod, string curveMod, string curve |
        (curveMod = "@noble/curves/p256" and curve = "p256") or
        (curveMod = "@noble/curves/p384" and curve = "p384") or
        (curveMod = "@noble/curves/p521" and curve = "p521")
      |
        mod = DataFlow::moduleMember(curveMod, curve) and
        (
          (call = mod.getAMemberCall("sign").asExpr() and algo = "ecdsa-" + curve) or
          (call = mod.getAMemberCall("verify").asExpr() and algo = "ecdsa-" + curve + "-verify") or
          (call = mod.getAMemberCall("getPublicKey").asExpr() and algo = "ec-" + curve + "-pubkey") or
          (call = mod.getAMemberCall("getSharedSecret").asExpr() and algo = "ecdh-" + curve)
        )
      )
    )

    or

    // bls12-381
    (
      api = "@noble/curves" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleMember("@noble/curves/bls12-381", "bls12_381") |
        (call = mod.getAMemberCall("sign").asExpr() and algo = "bls12-381-sign") or
        (call = mod.getAMemberCall("verify").asExpr() and algo = "bls12-381-verify") or
        (call = mod.getAMemberCall("getPublicKey").asExpr() and algo = "bls12-381-pubkey") or
        (call = mod.getAMemberCall("aggregateSignatures").asExpr() and algo = "bls12-381-aggregate")
      )
    )

    or

    // =============================================================================
    // @noble/secp256k1 (legacy, ~500k/wk)
    // =============================================================================
    (
      api = "@noble/secp256k1" and
      (
        (isModuleMethodCall(call, "@noble/secp256k1", "sign") and algo = "ecdsa-secp256k1") or
        (isModuleMethodCall(call, "@noble/secp256k1", "verify") and algo = "ecdsa-secp256k1-verify") or
        (isModuleMethodCall(call, "@noble/secp256k1", "getPublicKey") and algo = "ec-secp256k1-pubkey") or
        (isModuleMethodCall(call, "@noble/secp256k1", "getSharedSecret") and algo = "ecdh-secp256k1")
      )
    )

    or

    // =============================================================================
    // secp256k1 (native C++, ~1M/wk)
    // =============================================================================
    (
      api = "secp256k1" and
      (
        (isModuleMethodCall(call, "secp256k1", "ecdsaSign") and algo = "ecdsa-secp256k1") or
        (isModuleMethodCall(call, "secp256k1", "ecdsaVerify") and algo = "ecdsa-secp256k1-verify") or
        (isModuleMethodCall(call, "secp256k1", "ecdsaRecover") and algo = "ecdsa-secp256k1-recover") or
        (isModuleMethodCall(call, "secp256k1", "publicKeyCreate") and algo = "ec-secp256k1-pubkey") or
        (isModuleMethodCall(call, "secp256k1", "ecdh") and algo = "ecdh-secp256k1") or
        (isModuleMethodCall(call, "secp256k1", "privateKeyVerify") and algo = "ec-secp256k1-validate")
      )
    )

    or

    // =============================================================================
    // tiny-secp256k1 — peer dep for bitcoinjs-lib
    // =============================================================================
    (
      api = "tiny-secp256k1" and
      (
        (isModuleMethodCall(call, "tiny-secp256k1", "sign") and algo = "ecdsa-secp256k1") or
        (isModuleMethodCall(call, "tiny-secp256k1", "verify") and algo = "ecdsa-secp256k1-verify") or
        (isModuleMethodCall(call, "tiny-secp256k1", "signSchnorr") and algo = "schnorr-secp256k1") or
        (isModuleMethodCall(call, "tiny-secp256k1", "verifySchnorr") and algo = "schnorr-secp256k1-verify") or
        (isModuleMethodCall(call, "tiny-secp256k1", "pointFromScalar") and algo = "ec-secp256k1-pubkey") or
        (isModuleMethodCall(call, "tiny-secp256k1", "pointMultiply") and algo = "ecdh-secp256k1")
      )
    )

    or

    // =============================================================================
    // tweetnacl (~10M/wk) — compact NaCl implementation
    // =============================================================================
    (
      api = "tweetnacl" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("tweetnacl") |
        // box (x25519 + xsalsa20-poly1305)
        (call = mod.getAMemberCall("box").asExpr() and algo = "nacl-box-x25519-xsalsa20") or
        // secretbox (xsalsa20-poly1305)
        (call = mod.getAMemberCall("secretbox").asExpr() and algo = "nacl-secretbox-xsalsa20") or
        // sign (ed25519)
        (call = mod.getAMemberCall("sign").asExpr() and algo = "nacl-sign-ed25519") or
        // hash (sha512)
        (call = mod.getAMemberCall("hash").asExpr() and algo = "nacl-hash-sha512") or
        // randomBytes
        (call = mod.getAMemberCall("randomBytes").asExpr() and algo = "csprng-randomBytes")
      )
    )

    or

    // tweetnacl chained: nacl.box.keyPair(), nacl.sign.keyPair(), etc.
    (
      api = "tweetnacl" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("tweetnacl") |
        (call = mod.getAPropertyRead("box").getAMemberCall("keyPair").asExpr() and algo = "nacl-box-keygen-x25519") or
        (call = mod.getAPropertyRead("box").getAMemberCall("open").asExpr() and algo = "nacl-box-open-x25519-xsalsa20") or
        (call = mod.getAPropertyRead("box").getAMemberCall("before").asExpr() and algo = "nacl-box-beforenm-x25519") or
        (call = mod.getAPropertyRead("secretbox").getAMemberCall("open").asExpr() and algo = "nacl-secretbox-open-xsalsa20") or
        (call = mod.getAPropertyRead("sign").getAMemberCall("keyPair").asExpr() and algo = "nacl-sign-keygen-ed25519") or
        (call = mod.getAPropertyRead("sign").getAMemberCall("open").asExpr() and algo = "nacl-sign-open-ed25519") or
        (call = mod.getAPropertyRead("sign").getAMemberCall("detached").asExpr() and algo = "nacl-sign-detached-ed25519")
      )
    )

    or

    // =============================================================================
    // eccrypto (~50k/wk)
    // =============================================================================
    (
      api = "eccrypto" and
      (
        (isModuleMethodCall(call, "eccrypto", "encrypt") and algo = "ecies-secp256k1") or
        (isModuleMethodCall(call, "eccrypto", "decrypt") and algo = "ecies-secp256k1") or
        (isModuleMethodCall(call, "eccrypto", "sign") and algo = "ecdsa-secp256k1") or
        (isModuleMethodCall(call, "eccrypto", "verify") and algo = "ecdsa-secp256k1-verify") or
        (isModuleMethodCall(call, "eccrypto", "derive") and algo = "ecdh-secp256k1") or
        (isModuleMethodCall(call, "eccrypto", "generatePrivate") and algo = "ec-secp256k1-keygen")
      )
    )

    or

    // =============================================================================
    // node-forge (~15M/wk) — comprehensive crypto toolkit
    // Detects BOTH module imports (require/import) AND global variable access
    // (var forge = top.forge, window.forge, etc.)
    // =============================================================================

    // forge.cipher.createCipher / createDecipher
    (
      api = "node-forge" and
      isForgeSubsystemCall(call, "cipher", "createCipher") and
      call.getNumArgument() >= 1 and
      algo = "cipher-" + call.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )

    or

    (
      api = "node-forge" and
      isForgeSubsystemCall(call, "cipher", "createDecipher") and
      call.getNumArgument() >= 1 and
      algo = "decipher-" + call.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )

    or

    // forge.md.sha256.create(), forge.md.sha512.create(), etc.
    (
      api = "node-forge" and
      exists(string hashName |
        hashName = ["md5", "sha1", "sha256", "sha384", "sha512"] and
        isForgeDeepCall(call, "md", hashName, "create") and
        algo = hashName
      )
    )

    or

    // forge.hmac.create()
    (
      api = "node-forge" and
      isForgeSubsystemCall(call, "hmac", "create") and
      algo = "hmac"
    )

    or

    // forge.pki.rsa.generateKeyPair()
    (
      api = "node-forge" and
      isForgeDeepCall(call, "pki", "rsa", "generateKeyPair") and
      algo = "rsa-keygen"
    )

    or

    // forge.pkcs5.pbkdf2()
    (
      api = "node-forge" and
      isForgeSubsystemCall(call, "pkcs5", "pbkdf2") and
      algo = "pbkdf2"
    )

    or

    // forge.pki.createCertificate() / certificateFromPem() / etc.
    (
      api = "node-forge" and
      (
        (isForgeSubsystemCall(call, "pki", "createCertificate") and algo = "x509-create") or
        (isForgeSubsystemCall(call, "pki", "createCertificationRequest") and algo = "x509-csr") or
        (isForgeSubsystemCall(call, "pki", "certificateFromPem") and algo = "x509-parse") or
        (isForgeSubsystemCall(call, "pki", "certificateToPem") and algo = "x509-export")
      )
    )

    or

    // forge.random.getBytesSync / getBytes
    (
      api = "node-forge" and
      (
        (isForgeSubsystemCall(call, "random", "getBytesSync") and algo = "csprng-random") or
        (isForgeSubsystemCall(call, "random", "getBytes") and algo = "csprng-random")
      )
    )

    or

    // forge.pkcs12 / forge.pkcs7
    (
      api = "node-forge" and
      (
        (isForgeSubsystemCall(call, "pkcs12", "toPkcs12Asn1") and algo = "pkcs12-export") or
        (isForgeSubsystemCall(call, "pkcs12", "pkcs12FromAsn1") and algo = "pkcs12-import") or
        (isForgeSubsystemCall(call, "pkcs7", "createEnvelopedData") and algo = "pkcs7-envelope")
      )
    )

    or

    // forge.pss.create (RSA-PSS)
    (
      api = "node-forge" and
      isForgeSubsystemCall(call, "pss", "create") and
      algo = "rsa-pss"
    )

    or

    // forge.util.encode64 / decode64 (not crypto per se, but indicates forge is in use)
    // forge.pki.publicKeyFromPem / privateKeyFromPem / publicKeyToPem
    (
      api = "node-forge" and
      (
        (isForgeSubsystemCall(call, "pki", "publicKeyFromPem") and algo = "pubkey-import") or
        (isForgeSubsystemCall(call, "pki", "privateKeyFromPem") and algo = "privkey-import") or
        (isForgeSubsystemCall(call, "pki", "publicKeyToPem") and algo = "pubkey-export") or
        (isForgeSubsystemCall(call, "pki", "privateKeyToPem") and algo = "privkey-export") or
        (isForgeSubsystemCall(call, "pki", "createCaStore") and algo = "x509-ca-store")
      )
    )

    or

    // RSA encrypt/decrypt on a forge public/private key object
    // e.g. publicKey.encrypt(plaintext, 'RSAES-OAEP') or publicKey.encrypt(plaintext, 'RSAES-PKCS1-V1_5')
    // These are method calls on key objects, so we detect by method name + string arg in forge-using files
    (
      api = "node-forge" and
      call.getCalleeName() = "encrypt" and
      call instanceof MethodCallExpr and
      call.getNumArgument() >= 2 and
      exists(string padding |
        padding = call.getArgument(1).(StringLiteral).getValue() and
        (
          (padding = "RSAES-OAEP" and algo = "rsa-oaep") or
          (padding = "RSA-OAEP" and algo = "rsa-oaep") or
          (padding = "RSAES-PKCS1-V1_5" and algo = "rsa-pkcs1v15") or
          (padding = "NONE" and algo = "rsa-raw")
        )
      ) and
      // Guard: only match in files where forge is referenced
      exists(VarRef ref | ref.getName() = "forge" and ref.getFile() = call.getFile())
    )

    or

    // forge.aes.createDecryptionCipher / createEncryptionCipher
    (
      api = "node-forge" and
      (
        (isForgeSubsystemCall(call, "aes", "createDecryptionCipher") and algo = "aes-decrypt") or
        (isForgeSubsystemCall(call, "aes", "createEncryptionCipher") and algo = "aes-encrypt")
      )
    )

    or

    // =============================================================================
    // libsodium-wrappers (~2M/wk) — comprehensive libsodium bindings
    // =============================================================================
    (
      api = "libsodium-wrappers" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("libsodium-wrappers") or
        mod = DataFlow::moduleImport("libsodium-wrappers-sumo")
      |
        // Secretbox (xsalsa20-poly1305)
        (call = mod.getAMemberCall("crypto_secretbox_easy").asExpr() and algo = "secretbox-xsalsa20-poly1305") or
        (call = mod.getAMemberCall("crypto_secretbox_open_easy").asExpr() and algo = "secretbox-open-xsalsa20-poly1305") or
        (call = mod.getAMemberCall("crypto_secretbox_keygen").asExpr() and algo = "secretbox-keygen") or

        // Box (x25519 + xsalsa20-poly1305)
        (call = mod.getAMemberCall("crypto_box_easy").asExpr() and algo = "box-x25519-xsalsa20") or
        (call = mod.getAMemberCall("crypto_box_open_easy").asExpr() and algo = "box-open-x25519-xsalsa20") or
        (call = mod.getAMemberCall("crypto_box_keypair").asExpr() and algo = "box-keygen-x25519") or
        (call = mod.getAMemberCall("crypto_box_seal").asExpr() and algo = "box-seal-x25519") or
        (call = mod.getAMemberCall("crypto_box_seal_open").asExpr() and algo = "box-seal-open-x25519") or

        // AEAD
        (call = mod.getAMemberCall("crypto_aead_chacha20poly1305_encrypt").asExpr() and algo = "aead-chacha20-poly1305") or
        (call = mod.getAMemberCall("crypto_aead_chacha20poly1305_decrypt").asExpr() and algo = "aead-chacha20-poly1305") or
        (call = mod.getAMemberCall("crypto_aead_chacha20poly1305_ietf_encrypt").asExpr() and algo = "aead-chacha20-poly1305-ietf") or
        (call = mod.getAMemberCall("crypto_aead_chacha20poly1305_ietf_decrypt").asExpr() and algo = "aead-chacha20-poly1305-ietf") or
        (call = mod.getAMemberCall("crypto_aead_xchacha20poly1305_ietf_encrypt").asExpr() and algo = "aead-xchacha20-poly1305") or
        (call = mod.getAMemberCall("crypto_aead_xchacha20poly1305_ietf_decrypt").asExpr() and algo = "aead-xchacha20-poly1305") or

        // Signing (Ed25519)
        (call = mod.getAMemberCall("crypto_sign").asExpr() and algo = "sign-ed25519") or
        (call = mod.getAMemberCall("crypto_sign_open").asExpr() and algo = "sign-open-ed25519") or
        (call = mod.getAMemberCall("crypto_sign_detached").asExpr() and algo = "sign-detached-ed25519") or
        (call = mod.getAMemberCall("crypto_sign_verify_detached").asExpr() and algo = "sign-verify-ed25519") or
        (call = mod.getAMemberCall("crypto_sign_keypair").asExpr() and algo = "sign-keygen-ed25519") or
        (call = mod.getAMemberCall("crypto_sign_seed_keypair").asExpr() and algo = "sign-keygen-ed25519") or

        // Hashing
        (call = mod.getAMemberCall("crypto_hash").asExpr() and algo = "hash-sha512") or
        (call = mod.getAMemberCall("crypto_hash_sha256").asExpr() and algo = "hash-sha256") or
        (call = mod.getAMemberCall("crypto_hash_sha512").asExpr() and algo = "hash-sha512") or
        (call = mod.getAMemberCall("crypto_generichash").asExpr() and algo = "generichash-blake2b") or
        (call = mod.getAMemberCall("crypto_generichash_init").asExpr() and algo = "generichash-blake2b-init") or
        (call = mod.getAMemberCall("crypto_shorthash").asExpr() and algo = "shorthash-siphash24") or

        // Password hashing
        (call = mod.getAMemberCall("crypto_pwhash").asExpr() and algo = "pwhash-argon2") or
        (call = mod.getAMemberCall("crypto_pwhash_str").asExpr() and algo = "pwhash-argon2-str") or
        (call = mod.getAMemberCall("crypto_pwhash_str_verify").asExpr() and algo = "pwhash-argon2-verify") or
        (call = mod.getAMemberCall("crypto_pwhash_scryptsalsa208sha256").asExpr() and algo = "pwhash-scrypt") or

        // Key derivation / exchange
        (call = mod.getAMemberCall("crypto_kdf_keygen").asExpr() and algo = "kdf-keygen") or
        (call = mod.getAMemberCall("crypto_kdf_derive_from_key").asExpr() and algo = "kdf-derive") or
        (call = mod.getAMemberCall("crypto_kx_keypair").asExpr() and algo = "kx-keygen") or
        (call = mod.getAMemberCall("crypto_kx_client_session_keys").asExpr() and algo = "kx-client") or
        (call = mod.getAMemberCall("crypto_kx_server_session_keys").asExpr() and algo = "kx-server") or
        (call = mod.getAMemberCall("crypto_scalarmult").asExpr() and algo = "scalarmult-curve25519") or
        (call = mod.getAMemberCall("crypto_scalarmult_base").asExpr() and algo = "scalarmult-base-curve25519") or

        // Auth (HMAC)
        (call = mod.getAMemberCall("crypto_auth").asExpr() and algo = "auth-hmacsha512256") or
        (call = mod.getAMemberCall("crypto_auth_verify").asExpr() and algo = "auth-verify-hmacsha512256") or
        (call = mod.getAMemberCall("crypto_auth_hmacsha256").asExpr() and algo = "auth-hmacsha256") or
        (call = mod.getAMemberCall("crypto_auth_hmacsha512").asExpr() and algo = "auth-hmacsha512") or

        // Stream cipher
        (call = mod.getAMemberCall("crypto_stream_keygen").asExpr() and algo = "stream-xsalsa20-keygen") or
        (call = mod.getAMemberCall("crypto_stream_xor").asExpr() and algo = "stream-xsalsa20-xor") or

        // Random
        (call = mod.getAMemberCall("randombytes_buf").asExpr() and algo = "csprng-randombytes") or
        (call = mod.getAMemberCall("randombytes_buf_deterministic").asExpr() and algo = "drbg-deterministic") or
        (call = mod.getAMemberCall("randombytes_uniform").asExpr() and algo = "csprng-uniform")
      )
    )

    or

    // sodium-native — same API, different binding
    (
      api = "sodium-native" and
      exists(DataFlow::SourceNode mod, string methodName |
        mod = DataFlow::moduleImport("sodium-native") and
        call = mod.getAMemberCall(methodName).asExpr() and
        methodName.matches("crypto_%") and
        algo = methodName.replaceAll("crypto_", "")
      )
    )

    or

    // =============================================================================
    // sjcl (~100k/wk) — Stanford JS Crypto Library
    // =============================================================================

    // sjcl.encrypt / sjcl.decrypt (convenience API)
    (
      api = "sjcl" and
      (
        (isModuleMethodCall(call, "sjcl", "encrypt") and algo = "sjcl-encrypt-aes-ccm") or
        (isModuleMethodCall(call, "sjcl", "decrypt") and algo = "sjcl-decrypt-aes-ccm")
      )
    )

    or

    // sjcl.hash.sha256.hash(), sjcl.hash.sha512.hash(), etc.
    (
      api = "sjcl" and
      exists(DataFlow::SourceNode mod, string hashName |
        mod = DataFlow::moduleImport("sjcl") and
        hashName = ["sha1", "sha256", "sha512"] and
        call = mod.getAPropertyRead("hash").getAPropertyRead(hashName).getAMemberCall("hash").asExpr() and
        algo = hashName
      )
    )

    or

    // sjcl.misc.pbkdf2()
    (
      api = "sjcl" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("sjcl") and
        call = mod.getAPropertyRead("misc").getAMemberCall("pbkdf2").asExpr() and
        algo = "pbkdf2"
      )
    )

    or

    // sjcl.mode.ccm/gcm/ocb2.encrypt/decrypt
    (
      api = "sjcl" and
      exists(DataFlow::SourceNode mod, string modeName |
        mod = DataFlow::moduleImport("sjcl") and
        modeName = ["ccm", "gcm", "ocb2"] and
        (
          call = mod.getAPropertyRead("mode").getAPropertyRead(modeName).getAMemberCall("encrypt").asExpr() or
          call = mod.getAPropertyRead("mode").getAPropertyRead(modeName).getAMemberCall("decrypt").asExpr()
        ) and
        algo = "aes-" + modeName
      )
    )

    or

    // sjcl.random.randomWords()
    (
      api = "sjcl" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("sjcl") and
        call = mod.getAPropertyRead("random").getAMemberCall("randomWords").asExpr() and
        algo = "csprng-random"
      )
    )

    or

    // =============================================================================
    // @noble/ciphers (~800k/wk) — audited cipher library
    // =============================================================================
    (
      api = "@noble/ciphers" and
      (
        // AES
        (isNamedImportCall(call, "@noble/ciphers/aes", "aes_256_gcm") and algo = "aes-256-gcm") or
        (isNamedImportCall(call, "@noble/ciphers/aes", "aes_128_gcm") and algo = "aes-128-gcm") or
        (isNamedImportCall(call, "@noble/ciphers/aes", "aes_256_ctr") and algo = "aes-256-ctr") or
        (isNamedImportCall(call, "@noble/ciphers/aes", "aes_128_ctr") and algo = "aes-128-ctr") or
        (isNamedImportCall(call, "@noble/ciphers/aes", "aes_256_cbc") and algo = "aes-256-cbc") or
        (isNamedImportCall(call, "@noble/ciphers/aes", "aes_128_cbc") and algo = "aes-128-cbc") or
        (isNamedImportCall(call, "@noble/ciphers/aes", "aes_256_gcm_siv") and algo = "aes-256-gcm-siv") or

        // ChaCha
        (isNamedImportCall(call, "@noble/ciphers/chacha", "chacha20poly1305") and algo = "chacha20-poly1305") or
        (isNamedImportCall(call, "@noble/ciphers/chacha", "xchacha20poly1305") and algo = "xchacha20-poly1305") or

        // Salsa
        (isNamedImportCall(call, "@noble/ciphers/salsa", "xsalsa20poly1305") and algo = "xsalsa20-poly1305") or
        (isNamedImportCall(call, "@noble/ciphers/salsa", "salsa20") and algo = "salsa20") or

        // FF1
        (isNamedImportCall(call, "@noble/ciphers/ff1", "ff1") and algo = "ff1-fpe")
      )
    )

    or

    // =============================================================================
    // aes-js (~1M/wk) — pure JS AES
    // new aesjs.ModeOfOperation.ctr(key) etc.
    // =============================================================================
    (
      api = "aes-js" and
      call instanceof NewExpr and
      exists(DataFlow::SourceNode mod, string modeName |
        mod = DataFlow::moduleImport("aes-js") and
        modeName = ["ctr", "cbc", "cfb", "ofb", "ecb"] and
        call.(NewExpr).getCallee() =
          mod.getAPropertyRead("ModeOfOperation").getAPropertyRead(modeName).asExpr() and
        algo = "aes-" + modeName
      )
    )
  )
select call, "algo=" + algo + ", api=" + api
