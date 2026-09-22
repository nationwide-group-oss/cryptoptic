/**
 * @name Crypto inventory — Hashing, Password Hashing & KDF Libraries (JavaScript/TypeScript)
 * @description Inventory of third-party hashing, password hashing, and KDF library usage.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/javascript-cbom-hash-kdf
 * @tags security
 */

import javascript
import lib.CryptoCommon

from InvokeExpr call, string algo, string api
where
  (
    // =============================================================================
    // @noble/hashes (~3M/wk) — function-call API with named imports
    // =============================================================================

    // Hash functions: import { sha256 } from '@noble/hashes/sha256'; sha256(data)
    (isNamedImportCall(call, "@noble/hashes/sha256", "sha256") and algo = "sha256" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/sha256", "sha224") and algo = "sha224" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/sha512", "sha512") and algo = "sha512" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/sha512", "sha384") and algo = "sha384" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/sha512", "sha512_256") and algo = "sha512-256" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/sha1", "sha1") and algo = "sha1" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/sha3", "sha3_256") and algo = "sha3-256" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/sha3", "sha3_384") and algo = "sha3-384" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/sha3", "sha3_512") and algo = "sha3-512" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/sha3", "keccak_256") and algo = "keccak-256" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/sha3", "keccak_512") and algo = "keccak-512" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/blake2b", "blake2b") and algo = "blake2b" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/blake2s", "blake2s") and algo = "blake2s" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/blake3", "blake3") and algo = "blake3" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/ripemd160", "ripemd160") and algo = "ripemd160" and api = "@noble/hashes") or

    // HMAC: hmac(sha256, key, data)
    (isNamedImportCall(call, "@noble/hashes/hmac", "hmac") and algo = "hmac" and api = "@noble/hashes") or

    // KDFs
    (isNamedImportCall(call, "@noble/hashes/hkdf", "hkdf") and algo = "hkdf" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/pbkdf2", "pbkdf2") and algo = "pbkdf2" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/pbkdf2", "pbkdf2Async") and algo = "pbkdf2" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/scrypt", "scrypt") and algo = "scrypt" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/scrypt", "scryptAsync") and algo = "scrypt" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/argon2", "argon2id") and algo = "argon2id" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/argon2", "argon2i") and algo = "argon2i" and api = "@noble/hashes") or
    (isNamedImportCall(call, "@noble/hashes/argon2", "argon2d") and algo = "argon2d" and api = "@noble/hashes")

    or

    // =============================================================================
    // hash.js (~8M/wk) — chained API: hash.sha256().update(msg).digest()
    // We detect the initial hash.sha256() call.
    // =============================================================================
    (
      api = "hash.js" and
      call instanceof MethodCallExpr and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("hash.js") and
        (
          (call = mod.getAMemberCall("sha1").asExpr() and algo = "sha1") or
          (call = mod.getAMemberCall("sha224").asExpr() and algo = "sha224") or
          (call = mod.getAMemberCall("sha256").asExpr() and algo = "sha256") or
          (call = mod.getAMemberCall("sha384").asExpr() and algo = "sha384") or
          (call = mod.getAMemberCall("sha512").asExpr() and algo = "sha512") or
          (call = mod.getAMemberCall("ripemd160").asExpr() and algo = "ripemd160") or
          (call = mod.getAMemberCall("hmac").asExpr() and algo = "hmac")
        )
      )
    )

    or

    // =============================================================================
    // js-sha256 / js-sha512 / js-sha3 — function-call API
    // =============================================================================
    (isNamedImportCall(call, "js-sha256", "sha256") and algo = "sha256" and api = "js-sha256") or
    (isNamedImportCall(call, "js-sha256", "sha224") and algo = "sha224" and api = "js-sha256") or
    (isNamedImportCall(call, "js-sha512", "sha512") and algo = "sha512" and api = "js-sha512") or
    (isNamedImportCall(call, "js-sha512", "sha384") and algo = "sha384" and api = "js-sha512") or
    (isNamedImportCall(call, "js-sha512", "sha512_256") and algo = "sha512-256" and api = "js-sha512") or
    (isNamedImportCall(call, "js-sha512", "sha512_224") and algo = "sha512-224" and api = "js-sha512") or
    (isNamedImportCall(call, "js-sha3", "sha3_256") and algo = "sha3-256" and api = "js-sha3") or
    (isNamedImportCall(call, "js-sha3", "sha3_512") and algo = "sha3-512" and api = "js-sha3") or
    (isNamedImportCall(call, "js-sha3", "sha3_384") and algo = "sha3-384" and api = "js-sha3") or
    (isNamedImportCall(call, "js-sha3", "sha3_224") and algo = "sha3-224" and api = "js-sha3") or
    (isNamedImportCall(call, "js-sha3", "keccak256") and algo = "keccak-256" and api = "js-sha3") or
    (isNamedImportCall(call, "js-sha3", "keccak512") and algo = "keccak-512" and api = "js-sha3")

    or

    // =============================================================================
    // jsSHA — class-based: new jsSHA('SHA-256', 'TEXT')
    // =============================================================================
    (
      api = "jsSHA" and
      call instanceof NewExpr and
      (
        isModuleConstructorCall(call, "jssha", "default") or
        call.(NewExpr).getCalleeName() = "jsSHA"
      ) and
      call.getNumArgument() >= 1 and
      exists(string raw | raw = call.getArgument(0).(StringLiteral).getValue() |
        algo = raw.toLowerCase()
      )
    )

    or

    // =============================================================================
    // sha.js (~7M/wk) — shajs('sha256').update(data).digest()
    // The module export is a function that takes an algorithm name.
    // =============================================================================
    (
      api = "sha.js" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("sha.js") and
        call = mod.getACall().asExpr()
      ) and
      call.getNumArgument() >= 1 and
      algo = call.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )

    or

    // =============================================================================
    // md5 (npm, ~2M/wk) — md5(message)
    // =============================================================================
    (
      api = "md5" and
      algo = "md5" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("md5") and
        call = mod.getACall().asExpr()
      )
    )

    or

    // =============================================================================
    // keccak (npm, ~2M/wk) — createKeccakHash('keccak256')
    // =============================================================================
    (
      api = "keccak" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("keccak") and
        call = mod.getACall().asExpr()
      ) and
      call.getNumArgument() >= 1 and
      algo = call.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )

    or

    // =============================================================================
    // blake3 (npm) — blake3.hash(data), blake3.keyedHash(), blake3.deriveKey()
    // =============================================================================
    (
      api = "blake3" and
      (
        (isModuleMethodCall(call, "blake3", "hash") and algo = "blake3") or
        (isModuleMethodCall(call, "blake3", "keyedHash") and algo = "blake3-keyed") or
        (isModuleMethodCall(call, "blake3", "deriveKey") and algo = "blake3-kdf") or
        (isModuleMethodCall(call, "blake3", "createHash") and algo = "blake3-stream") or
        (isModuleMethodCall(call, "blake3", "createKeyed") and algo = "blake3-keyed-stream")
      )
    )

    or

    // =============================================================================
    // create-hash / create-hmac (~7M/wk) — browserify polyfills
    // Same API as node:crypto but from a separate package.
    // =============================================================================
    (
      api = "create-hash" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("create-hash") and
        call = mod.getACall().asExpr()
      ) and
      call.getNumArgument() >= 1 and
      algo = call.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )

    or

    (
      api = "create-hmac" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("create-hmac") and
        call = mod.getACall().asExpr()
      ) and
      call.getNumArgument() >= 1 and
      algo = "hmac-" + call.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )

    or

    // =============================================================================
    // bcrypt (~1.5M/wk) — native C++ addon
    // =============================================================================
    (
      api = "bcrypt" and
      (
        (isModuleMethodCall(call, "bcrypt", "hash") and algo = "bcrypt-hash") or
        (isModuleMethodCall(call, "bcrypt", "hashSync") and algo = "bcrypt-hash") or
        (isModuleMethodCall(call, "bcrypt", "compare") and algo = "bcrypt-verify") or
        (isModuleMethodCall(call, "bcrypt", "compareSync") and algo = "bcrypt-verify") or
        (isModuleMethodCall(call, "bcrypt", "genSalt") and algo = "bcrypt-gensalt") or
        (isModuleMethodCall(call, "bcrypt", "genSaltSync") and algo = "bcrypt-gensalt")
      )
    )

    or

    // =============================================================================
    // bcryptjs (~1.5M/wk) — pure JS bcrypt
    // =============================================================================
    (
      api = "bcryptjs" and
      (
        (isModuleMethodCall(call, "bcryptjs", "hash") and algo = "bcrypt-hash") or
        (isModuleMethodCall(call, "bcryptjs", "hashSync") and algo = "bcrypt-hash") or
        (isModuleMethodCall(call, "bcryptjs", "compare") and algo = "bcrypt-verify") or
        (isModuleMethodCall(call, "bcryptjs", "compareSync") and algo = "bcrypt-verify") or
        (isModuleMethodCall(call, "bcryptjs", "genSalt") and algo = "bcrypt-gensalt") or
        (isModuleMethodCall(call, "bcryptjs", "genSaltSync") and algo = "bcrypt-gensalt")
      )
    )

    or

    // =============================================================================
    // argon2 (~300k/wk) — native addon, PHC winner
    // =============================================================================
    (
      api = "argon2" and
      (
        // argon2.hash() — type in options: { type: argon2.argon2id }
        (
          isModuleMethodCall(call, "argon2", "hash") and
          (
            exists(PropAccess typeAccess |
              typeAccess = call.getArgument(1).(ObjectExpr).getPropertyByName("type").getInit() and
              (
                (typeAccess.getPropertyName() = "argon2id" and algo = "argon2id") or
                (typeAccess.getPropertyName() = "argon2i" and algo = "argon2i") or
                (typeAccess.getPropertyName() = "argon2d" and algo = "argon2d")
              )
            )
            or
            (
              not exists(call.getArgument(1).(ObjectExpr).getPropertyByName("type").getInit().(PropAccess)) and
              algo = "argon2id" // default
            )
          )
        )
        or
        (isModuleMethodCall(call, "argon2", "verify") and algo = "argon2-verify")
        or
        (isModuleMethodCall(call, "argon2", "needsRehash") and algo = "argon2-rehash-check")
      )
    )

    or

    // =============================================================================
    // scrypt-js (~1M/wk) — pure JS scrypt
    // =============================================================================
    (
      api = "scrypt-js" and
      algo = "scrypt" and
      (
        isModuleMethodCall(call, "scrypt-js", "scrypt") or
        isModuleMethodCall(call, "scrypt-js", "syncScrypt") or
        exists(DataFlow::SourceNode mod |
          mod = DataFlow::moduleImport("scrypt-js") and
          call = mod.getACall().asExpr()
        )
      )
    )

    or

    // =============================================================================
    // Browserify polyfills — additional packages
    // =============================================================================

    // randombytes (~10M/wk)
    (
      api = "randombytes" and
      algo = "csprng-randomBytes" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("randombytes") and
        call = mod.getACall().asExpr()
      )
    )

    or

    // browserify-aes (~6M/wk)
    (
      api = "browserify-aes" and
      (
        isModuleMethodCall(call, "browserify-aes", "createCipheriv") or
        isModuleMethodCall(call, "browserify-aes", "createDecipheriv")
      ) and
      call.getNumArgument() >= 1 and
      algo = call.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )

    or

    // pbkdf2 (npm, ~6M/wk)
    (
      api = "pbkdf2" and
      (
        isModuleMethodCall(call, "pbkdf2", "pbkdf2") or
        isModuleMethodCall(call, "pbkdf2", "pbkdf2Sync")
      ) and
      call.getNumArgument() >= 5 and
      algo = "pbkdf2-" + call.getArgument(4).(StringLiteral).getValue().toLowerCase()
    )

    or

    // browserify-sign (~5M/wk)
    (
      api = "browserify-sign" and
      (
        isModuleMethodCall(call, "browserify-sign", "createSign") or
        isModuleMethodCall(call, "browserify-sign", "createVerify")
      ) and
      call.getNumArgument() >= 1 and
      algo = call.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )

    or

    // browserify-cipher (~5M/wk)
    (
      api = "browserify-cipher" and
      (
        isModuleMethodCall(call, "browserify-cipher", "createCipher") or
        isModuleMethodCall(call, "browserify-cipher", "createDecipher") or
        isModuleMethodCall(call, "browserify-cipher", "createCipheriv") or
        isModuleMethodCall(call, "browserify-cipher", "createDecipheriv")
      ) and
      call.getNumArgument() >= 1 and
      algo = call.getArgument(0).(StringLiteral).getValue().toLowerCase()
    )

    or

    // crypto-browserify (~5M/wk) — full polyfill
    // Method calls on the polyfill are detected via import tracking.
    // We catch the most important ones that would otherwise be misattributed to node:crypto.
    (
      api = "crypto-browserify" and
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport("crypto-browserify") |
        (
          (call = mod.getAMemberCall("createHash").asExpr() and
           call.getNumArgument() >= 1 and
           algo = getArgValue(call, 0))
          or
          (call = mod.getAMemberCall("createHmac").asExpr() and
           call.getNumArgument() >= 1 and
           algo = "hmac-" + getArgValue(call, 0))
          or
          (call = mod.getAMemberCall("createCipheriv").asExpr() and
           call.getNumArgument() >= 1 and
           algo = getArgValue(call, 0))
          or
          (call = mod.getAMemberCall("createDecipheriv").asExpr() and
           call.getNumArgument() >= 1 and
           algo = getArgValue(call, 0))
          or
          (call = mod.getAMemberCall("randomBytes").asExpr() and algo = "csprng-randomBytes")
          or
          (call = mod.getAMemberCall("pbkdf2").asExpr() and algo = "pbkdf2")
          or
          (call = mod.getAMemberCall("pbkdf2Sync").asExpr() and algo = "pbkdf2")
        )
      )
    )

    or

    // =============================================================================
    // Non-cryptographic hashes (optional — flag potential misuse)
    // =============================================================================

    // xxhash-wasm
    (isNamedImportCall(call, "xxhash-wasm", "h32") and algo = "xxh32 [non-crypto]" and api = "xxhash-wasm") or
    (isNamedImportCall(call, "xxhash-wasm", "h64") and algo = "xxh64 [non-crypto]" and api = "xxhash-wasm") or

    // murmurhash
    (isModuleMethodCall(call, "murmurhash", "v2") and algo = "murmur2 [non-crypto]" and api = "murmurhash") or
    (isModuleMethodCall(call, "murmurhash", "v3") and algo = "murmur3 [non-crypto]" and api = "murmurhash")
  )
select call, "algo=" + algo + ", api=" + api
