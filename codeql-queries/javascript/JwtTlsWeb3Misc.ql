/**
 * @name Crypto inventory — JWT, TLS, Web3, OpenPGP & Misc (JavaScript/TypeScript)
 * @description Inventory of JWT/JOSE, TLS, Web3/blockchain, OpenPGP, and
 *              miscellaneous crypto-consuming library usage.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/javascript-cbom-jwt-tls-web3-misc
 * @tags security
 */

import javascript
import lib.CryptoCommon

from InvokeExpr call, string algo, string api
where
  (
    // =============================================================================
    // jsonwebtoken (~15M/wk)
    // jwt.sign(payload, key, { algorithm: 'RS256' })
    // jwt.verify(token, key, { algorithms: ['RS256'] })
    // =============================================================================
    (
      api = "jsonwebtoken" and
      (
        // jwt.sign with explicit algorithm option
        (
          isModuleMethodCall(call, "jsonwebtoken", "sign") and
          (
            exists(string alg | alg = getOptionsProperty(call, 2, "algorithm") |
              algo = "jwt-sign-" + alg.toLowerCase()
            )
            or
            // No explicit algorithm → default HS256
            (
              not exists(getOptionsProperty(call, 2, "algorithm")) and
              algo = "jwt-sign-hs256"
            )
          )
        )
        or
        // jwt.verify
        (
          isModuleMethodCall(call, "jsonwebtoken", "verify") and
          (
            // Explicit algorithms array — report each
            exists(ArrayExpr arr, StringLiteral alg |
              (call.getArgument(2).(ObjectExpr).getPropertyByName("algorithms").getInit() = arr or
               call.getArgument(2).(ObjectExpr).getPropertyByName("algorithms").getInit().flow().getALocalSource().asExpr() = arr) and
              alg = arr.getAnElement() and
              algo = "jwt-verify-" + alg.getValue().toLowerCase()
            )
            or
            // No explicit algorithms
            (
              not exists(call.getArgument(2).(ObjectExpr).getPropertyByName("algorithms")) and
              algo = "jwt-verify"
            )
          )
        )
        or
        // jwt.decode (insecure — no verification)
        (isModuleMethodCall(call, "jsonwebtoken", "decode") and algo = "jwt-decode-unverified")
      )
    )

    or

    // =============================================================================
    // jose (~8M/wk) — modern JOSE library
    // new SignJWT(payload).setProtectedHeader({ alg: 'ES256' }).sign(key)
    // =============================================================================

    // SignJWT — detect the setProtectedHeader call to get the algorithm
    (
      api = "jose" and
      call.getCalleeName() = "setProtectedHeader" and
      exists(DataFlow::SourceNode jose |
        jose = DataFlow::moduleImport("jose")
      ) and
      fileImportsModule(call, "jose") and
      exists(string alg |
        alg = call.getArgument(0).(ObjectExpr).getPropertyByName("alg").getInit().(StringLiteral).getValue() and
        algo = "jose-sign-" + alg.toLowerCase()
      )
    )

    or

    // jose key generation: generateKeyPair('RS256'), generateKeyPair('ES256')
    (
      api = "jose" and
      isNamedImportCall(call, "jose", "generateKeyPair") and
      call.getNumArgument() >= 1 and
      algo = "jose-keygen-" + call.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )

    or

    // jose verify
    (
      api = "jose" and
      isNamedImportCall(call, "jose", "jwtVerify") and
      algo = "jose-jwt-verify"
    )

    or

    // jose encrypt (JWE) — detect the header for alg + enc
    (
      api = "jose" and
      call.getCalleeName() = "setProtectedHeader" and
      fileImportsModule(call, "jose") and
      exists(ObjectExpr header |
        header = call.getArgument(0) and
        exists(string alg, string enc |
          alg = header.getPropertyByName("alg").getInit().(StringLiteral).getValue() and
          enc = header.getPropertyByName("enc").getInit().(StringLiteral).getValue() and
          algo = "jose-encrypt-" + alg.toLowerCase() + "-" + enc.toLowerCase()
        )
      )
    )

    or

    // jose key import/export
    (
      api = "jose" and
      (
        (isNamedImportCall(call, "jose", "importPKCS8") and algo = "jose-import-pkcs8") or
        (isNamedImportCall(call, "jose", "importSPKI") and algo = "jose-import-spki") or
        (isNamedImportCall(call, "jose", "importJWK") and algo = "jose-import-jwk") or
        (isNamedImportCall(call, "jose", "exportJWK") and algo = "jose-export-jwk") or
        (isNamedImportCall(call, "jose", "importX509") and algo = "jose-import-x509")
      )
    )

    or

    // =============================================================================
    // passport-jwt — JwtStrategy with algorithms option
    // =============================================================================
    (
      api = "passport-jwt" and
      call instanceof NewExpr and
      call.(NewExpr).getCalleeName() = ["JwtStrategy", "Strategy"] and
      fileImportsModule(call, "passport-jwt") and
      (
        exists(ArrayExpr arr, StringLiteral alg |
          call.getArgument(0).(ObjectExpr).getPropertyByName("algorithms").getInit() = arr and
          alg = arr.getAnElement() and
          algo = "passport-jwt-" + alg.getValue().toLowerCase()
        )
        or
        (
          not exists(call.getArgument(0).(ObjectExpr).getPropertyByName("algorithms")) and
          algo = "passport-jwt"
        )
      )
    )

    or

    // =============================================================================
    // express-jwt — expressjwt({ algorithms: ['RS256'] })
    // =============================================================================
    (
      api = "express-jwt" and
      (
        isNamedImportCall(call, "express-jwt", "expressjwt") or
        isNamedImportCall(call, "express-jwt", "default")
      ) and
      (
        exists(ArrayExpr arr, StringLiteral alg |
          call.getArgument(0).(ObjectExpr).getPropertyByName("algorithms").getInit() = arr and
          alg = arr.getAnElement() and
          algo = "express-jwt-" + alg.getValue().toLowerCase()
        )
        or
        (
          not exists(call.getArgument(0).(ObjectExpr).getPropertyByName("algorithms")) and
          algo = "express-jwt"
        )
      )
    )

    or

    // =============================================================================
    // node:tls — TLS server/client configuration
    // =============================================================================

    // tls.createServer / tls.createSecureContext / tls.connect
    (
      api = "node:tls" and
      exists(DataFlow::SourceNode mod |
        (mod = DataFlow::moduleImport("tls") or mod = DataFlow::moduleImport("node:tls")) and
        (
          call = mod.getAMemberCall("createServer").asExpr() or
          call = mod.getAMemberCall("createSecureContext").asExpr() or
          call = mod.getAMemberCall("connect").asExpr()
        )
      ) and
      call.getNumArgument() >= 1 and
      (
        // Extract minVersion
        exists(string ver |
          ver = getOptionsProperty(call, 0, "minVersion") and
          algo = "tls-minVersion-" + ver
        )
        or
        // Extract maxVersion
        exists(string ver |
          ver = getOptionsProperty(call, 0, "maxVersion") and
          algo = "tls-maxVersion-" + ver
        )
        or
        // Extract ciphers string
        exists(string ciphers |
          ciphers = getOptionsProperty(call, 0, "ciphers") and
          algo = "tls-ciphers"
        )
        or
        // No TLS config options resolvable but call exists
        (
          not exists(getOptionsProperty(call, 0, "minVersion")) and
          not exists(getOptionsProperty(call, 0, "maxVersion")) and
          not exists(getOptionsProperty(call, 0, "ciphers")) and
          algo = "tls-config"
        )
      )
    )

    or

    // https.createServer / new https.Agent (delegates to TLS)
    (
      api = "node:https" and
      exists(DataFlow::SourceNode mod |
        (mod = DataFlow::moduleImport("https") or mod = DataFlow::moduleImport("node:https")) and
        (
          (call = mod.getAMemberCall("createServer").asExpr() and algo = "https-server") or
          (call instanceof NewExpr and
           call.(NewExpr).getCallee() = mod.getAPropertyRead("Agent").asExpr() and
           algo = "https-agent")
        )
      )
    )

    or

    // =============================================================================
    // @peculiar/x509 — modern X.509 library
    // =============================================================================
    (
      api = "@peculiar/x509" and
      (
        (isNamedImportCall(call, "@peculiar/x509", "X509CertificateGenerator") and algo = "x509-generate") or
        (isModuleMethodCall(call, "@peculiar/x509", "createSelfSigned") and algo = "x509-self-signed") or
        (isNamedImportCall(call, "@peculiar/x509", "Pkcs10CertificateRequestGenerator") and algo = "x509-csr") or
        (isModuleConstructorCall(call, "@peculiar/x509", "X509Certificate") and algo = "x509-parse") or
        (isModuleConstructorCall(call, "@peculiar/x509", "X509ChainBuilder") and algo = "x509-chain") or
        (isNamedImportCall(call, "@peculiar/x509", "X509CrlGenerator") and algo = "x509-crl")
      )
    )

    or

    // selfsigned (~4M/wk)
    (
      api = "selfsigned" and
      isModuleMethodCall(call, "selfsigned", "generate") and
      (
        exists(string alg |
          alg = getOptionsProperty(call, 1, "algorithm") and
          algo = "selfsigned-" + alg.toLowerCase()
        )
        or
        (not exists(getOptionsProperty(call, 1, "algorithm")) and algo = "selfsigned-sha1")
      )
    )

    or

    // =============================================================================
    // openpgp (~300k/wk)
    // =============================================================================
    (
      api = "openpgp" and
      (
        // generateKey — extract type and curve
        (
          isModuleMethodCall(call, "openpgp", "generateKey") and
          (
            exists(string keyType |
              keyType = getOptionsProperty(call, 0, "type") and
              (
                exists(string curve |
                  curve = getOptionsProperty(call, 0, "curve") and
                  algo = "pgp-keygen-" + keyType + "-" + curve.toLowerCase()
                )
                or
                (not exists(getOptionsProperty(call, 0, "curve")) and algo = "pgp-keygen-" + keyType)
              )
            )
            or
            (not exists(getOptionsProperty(call, 0, "type")) and algo = "pgp-keygen")
          )
        )
        or
        (isModuleMethodCall(call, "openpgp", "encrypt") and algo = "pgp-encrypt") or
        (isModuleMethodCall(call, "openpgp", "decrypt") and algo = "pgp-decrypt") or
        (isModuleMethodCall(call, "openpgp", "sign") and algo = "pgp-sign") or
        (isModuleMethodCall(call, "openpgp", "verify") and algo = "pgp-verify") or
        (isModuleMethodCall(call, "openpgp", "readKey") and algo = "pgp-read-key") or
        (isModuleMethodCall(call, "openpgp", "readPrivateKey") and algo = "pgp-read-private-key") or
        (isModuleMethodCall(call, "openpgp", "decryptKey") and algo = "pgp-decrypt-key") or
        (isModuleMethodCall(call, "openpgp", "createMessage") and algo = "pgp-create-message") or
        (isModuleMethodCall(call, "openpgp", "readMessage") and algo = "pgp-read-message")
      )
    )

    or

    // =============================================================================
    // age-encryption (~20k/wk)
    // =============================================================================
    (
      api = "age-encryption" and
      (
        (isModuleMethodCall(call, "age-encryption", "encrypt") and algo = "age-encrypt-x25519") or
        (isModuleMethodCall(call, "age-encryption", "decrypt") and algo = "age-decrypt") or
        (isModuleMethodCall(call, "age-encryption", "generateIdentity") and algo = "age-keygen-x25519") or
        (isModuleMethodCall(call, "age-encryption", "identityToRecipient") and algo = "age-identity-to-recipient")
      )
    )

    or

    // =============================================================================
    // ethers.js v6 (~3M/wk)
    // =============================================================================
    (
      api = "ethers" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("ethers") |
        // Hashing
        (call = mod.getAMemberCall("keccak256").asExpr() and algo = "keccak256") or
        (call = mod.getAMemberCall("sha256").asExpr() and algo = "sha256") or
        (call = mod.getAMemberCall("sha512").asExpr() and algo = "sha512") or
        (call = mod.getAMemberCall("ripemd160").asExpr() and algo = "ripemd160") or
        (call = mod.getAMemberCall("id").asExpr() and algo = "keccak256") or
        (call = mod.getAMemberCall("solidityPackedKeccak256").asExpr() and algo = "keccak256") or
        (call = mod.getAMemberCall("solidityPackedSha256").asExpr() and algo = "sha256") or
        (call = mod.getAMemberCall("hashMessage").asExpr() and algo = "keccak256-eip191") or

        // HMAC / KDF
        (call = mod.getAMemberCall("computeHmac").asExpr() and algo = "hmac") or
        (call = mod.getAMemberCall("pbkdf2").asExpr() and algo = "pbkdf2") or
        (call = mod.getAMemberCall("scrypt").asExpr() and algo = "scrypt") or

        // Wallet / Signing (secp256k1)
        (call = mod.getAMemberCall("computeAddress").asExpr() and algo = "ec-secp256k1-address") or
        (call = mod.getAMemberCall("randomBytes").asExpr() and algo = "csprng-randomBytes")
      )
    )

    or

    // ethers Wallet class
    (
      api = "ethers" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("ethers") |
        (call = mod.getAPropertyRead("Wallet").getAMemberCall("createRandom").asExpr() and algo = "ec-secp256k1-keygen") or
        (call = mod.getAPropertyRead("Wallet").getAMemberCall("fromEncryptedJson").asExpr() and algo = "wallet-decrypt-aes128ctr-scrypt")
      )
    )

    or

    // ethers Wallet instance methods (signMessage, signTransaction, encrypt)
    (
      api = "ethers" and
      fileImportsModule(call, "ethers") and
      (
        (call.getCalleeName() = "signMessage" and algo = "ecdsa-secp256k1-sign") or
        (call.getCalleeName() = "signTransaction" and algo = "ecdsa-secp256k1-sign") or
        (call.getCalleeName() = "signTypedData" and algo = "ecdsa-secp256k1-eip712")
      ) and
      // Guard: only match in files that import ethers to avoid false positives
      // on generic "signMessage" calls
      call instanceof MethodCallExpr
    )

    or

    // ethers SigningKey
    (
      api = "ethers" and
      call instanceof NewExpr and
      call.(NewExpr).getCalleeName() = "SigningKey" and
      fileImportsModule(call, "ethers") and
      algo = "ec-secp256k1-signingkey"
    )

    or

    // ethers HDNodeWallet / Mnemonic
    (
      api = "ethers" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("ethers") |
        (call = mod.getAPropertyRead("HDNodeWallet").getAMemberCall("fromMnemonic").asExpr() and algo = "hdwallet-bip32-secp256k1") or
        (call = mod.getAPropertyRead("Mnemonic").getAMemberCall("fromEntropy").asExpr() and algo = "mnemonic-bip39")
      )
    )

    or

    // ethers.js v5 (legacy) — utils.keccak256, utils.sha256, etc.
    (
      api = "ethers" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("ethers") |
        (call = mod.getAPropertyRead("utils").getAMemberCall("keccak256").asExpr() and algo = "keccak256") or
        (call = mod.getAPropertyRead("utils").getAMemberCall("sha256").asExpr() and algo = "sha256") or
        (call = mod.getAPropertyRead("utils").getAMemberCall("computeHmac").asExpr() and algo = "hmac") or
        (call = mod.getAPropertyRead("utils").getAMemberCall("pbkdf2").asExpr() and algo = "pbkdf2") or
        (call = mod.getAPropertyRead("utils").getAMemberCall("randomBytes").asExpr() and algo = "csprng-randomBytes") or
        (call = mod.getAPropertyRead("utils").getAPropertyRead("HDNode").getAMemberCall("fromMnemonic").asExpr() and algo = "hdwallet-bip32-secp256k1")
      )
    )

    or

    // =============================================================================
    // web3.js (~1M/wk)
    // =============================================================================
    (
      api = "web3" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("web3") |
        // web3.utils hashing
        (call = mod.getAPropertyRead("utils").getAMemberCall("keccak256").asExpr() and algo = "keccak256") or
        (call = mod.getAPropertyRead("utils").getAMemberCall("sha3").asExpr() and algo = "keccak256") or
        (call = mod.getAPropertyRead("utils").getAMemberCall("soliditySha3").asExpr() and algo = "keccak256-solidity") or
        (call = mod.getAPropertyRead("utils").getAMemberCall("randomHex").asExpr() and algo = "csprng-randomHex")
      )
    )

    or

    // web3.eth.accounts operations
    (
      api = "web3" and
      call instanceof MethodCallExpr and
      fileImportsModule(call, "web3") and
      call.getCalleeName() = ["create", "sign", "signTransaction", "recover", "encrypt", "decrypt", "hashMessage"] and
      // Heuristic: check that receiver chain contains "accounts"
      call.(MethodCallExpr).getReceiver().(PropAccess).getPropertyName() = "accounts" and
      (
        (call.getCalleeName() = "create" and algo = "ec-secp256k1-keygen") or
        (call.getCalleeName() = "sign" and algo = "ecdsa-secp256k1") or
        (call.getCalleeName() = "signTransaction" and algo = "ecdsa-secp256k1") or
        (call.getCalleeName() = "recover" and algo = "ecdsa-secp256k1-recover") or
        (call.getCalleeName() = "encrypt" and algo = "keystore-v3-aes128ctr-scrypt") or
        (call.getCalleeName() = "decrypt" and algo = "keystore-v3-decrypt") or
        (call.getCalleeName() = "hashMessage" and algo = "keccak256-eip191")
      )
    )

    or

    // =============================================================================
    // bitcoinjs-lib (~200k/wk)
    // =============================================================================
    (
      api = "bitcoinjs-lib" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("bitcoinjs-lib") |
        // Payment address generation
        (call = mod.getAPropertyRead("payments").getAMemberCall("p2pkh").asExpr() and algo = "btc-p2pkh-hash160") or
        (call = mod.getAPropertyRead("payments").getAMemberCall("p2wpkh").asExpr() and algo = "btc-p2wpkh-hash160") or
        (call = mod.getAPropertyRead("payments").getAMemberCall("p2tr").asExpr() and algo = "btc-p2tr-schnorr")
      )
    )

    or

    // bitcoinjs Psbt (Partially Signed Bitcoin Transaction)
    (
      api = "bitcoinjs-lib" and
      call instanceof NewExpr and
      call.(NewExpr).getCalleeName() = "Psbt" and
      fileImportsModule(call, "bitcoinjs-lib") and
      algo = "btc-psbt"
    )

    or

    // ecpair (bitcoinjs key management)
    (
      api = "ecpair" and
      isModuleMethodCall(call, "ecpair", "ECPairFactory") and
      algo = "ec-secp256k1-keypair-factory"
    )

    or

    // bip32 (HD key derivation for Bitcoin)
    (
      api = "bip32" and
      isModuleMethodCall(call, "bip32", "BIP32Factory") and
      algo = "bip32-hdkey-factory"
    )

    or

    // bip39 (mnemonic generation)
    (
      api = "bip39" and
      (
        (isModuleMethodCall(call, "bip39", "generateMnemonic") and algo = "bip39-mnemonic-gen") or
        (isModuleMethodCall(call, "bip39", "mnemonicToSeed") and algo = "bip39-mnemonic-to-seed-pbkdf2") or
        (isModuleMethodCall(call, "bip39", "mnemonicToSeedSync") and algo = "bip39-mnemonic-to-seed-pbkdf2") or
        (isModuleMethodCall(call, "bip39", "validateMnemonic") and algo = "bip39-validate")
      )
    )

    or

    // =============================================================================
    // uuid (~60M/wk)
    // =============================================================================
    (
      api = "uuid" and
      (
        (isNamedImportCall(call, "uuid", "v4") and algo = "uuid-v4-csprng") or
        (isNamedImportCall(call, "uuid", "v1") and algo = "uuid-v1-timestamp") or
        (isNamedImportCall(call, "uuid", "v5") and algo = "uuid-v5-sha1") or
        (isNamedImportCall(call, "uuid", "v3") and algo = "uuid-v3-md5") or
        (isNamedImportCall(call, "uuid", "v7") and algo = "uuid-v7-csprng")
      )
    )

    or

    // =============================================================================
    // nanoid (~15M/wk)
    // =============================================================================
    (
      api = "nanoid" and
      (
        (isNamedImportCall(call, "nanoid", "nanoid") and algo = "csprng-nanoid") or
        (isNamedImportCall(call, "nanoid", "customAlphabet") and algo = "csprng-nanoid-custom")
      )
    )

    or

    // nanoid non-secure (Math.random — flag as insecure)
    (
      api = "nanoid" and
      isNamedImportCall(call, "nanoid/non-secure", "nanoid") and
      algo = "insecure-nanoid-math-random"
    )

    or

    // =============================================================================
    // crypto-random-string (~1M/wk)
    // =============================================================================
    (
      api = "crypto-random-string" and
      algo = "csprng-random-string" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("crypto-random-string") and
        call = mod.getACall().asExpr()
      )
    )

    or

    // =============================================================================
    // cuid2 (~500k/wk)
    // =============================================================================
    (
      api = "@paralleldrive/cuid2" and
      (
        (isNamedImportCall(call, "@paralleldrive/cuid2", "createId") and algo = "cuid2-sha3") or
        (isNamedImportCall(call, "@paralleldrive/cuid2", "init") and algo = "cuid2-sha3-custom")
      )
    )

    or

    // =============================================================================
    // ulid (~300k/wk)
    // =============================================================================
    (
      api = "ulid" and
      (
        (isNamedImportCall(call, "ulid", "ulid") and algo = "ulid-csprng") or
        (isNamedImportCall(call, "ulid", "monotonicFactory") and algo = "ulid-monotonic-csprng")
      )
    )

    or

    // =============================================================================
    // keypair (~200k/wk) — RSA key pair generation
    // =============================================================================
    (
      api = "keypair" and
      algo = "rsa-keygen" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("keypair") and
        call = mod.getACall().asExpr()
      )
    )

    or

    // =============================================================================
    // Math.random() — insecure randomness, not a CSPRNG
    // Flags usage in files that also use crypto, since it likely indicates
    // insecure random being used where crypto random should be.
    // =============================================================================
    (
      api = "Math" and
      algo = "insecure-math-random" and
      call.getCalleeName() = "random" and
      call instanceof MethodCallExpr and
      call.(MethodCallExpr).getReceiver().(VarRef).getName() = "Math"
    )
  )
select call, "algo=" + algo + ", api=" + api
