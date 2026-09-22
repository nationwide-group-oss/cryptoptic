/**
 * @name Crypto inventory — node:crypto (JavaScript/TypeScript)
 * @description Inventory of Node.js crypto module usage with algorithm detection.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/javascript-cbom-node-crypto
 * @tags security
 */

import javascript
import lib.CryptoCommon

/**
 * Holds if the callee name is one of the tracked node:crypto function names,
 * OR if the call is an aliased reference to a crypto method.
 * Used as the first filter for performance.
 */
predicate isCandidateNodeCryptoCall(InvokeExpr call) {
  call.getCalleeName() in [
    "createHash", "hash", "createHmac",
    "hkdf", "hkdfSync", "pbkdf2", "pbkdf2Sync", "scrypt", "scryptSync",
    "createCipheriv", "createDecipheriv", "createCipher", "createDecipher",
    "createSign", "createVerify", "sign", "verify",
    "publicEncrypt", "privateDecrypt", "privateEncrypt", "publicDecrypt",
    "generateKeyPair", "generateKeyPairSync", "generateKey", "generateKeySync",
    "createDiffieHellman", "createDiffieHellmanGroup", "getDiffieHellman",
    "createECDH", "diffieHellman",
    "createSecretKey", "createPublicKey", "createPrivateKey",
    "randomBytes", "randomFill", "randomFillSync", "randomInt"
  ]
  or
  call instanceof NewExpr and call.(NewExpr).getCalleeName() = "X509Certificate"
  or
  // Aliased or renamed destructured imports
  isAliasedCryptoCall(call, _)
  or
  isDestructuredCryptoCall(call, _)
}

/**
 * Holds when the call matches a node:crypto pattern AND the algorithm is resolvable.
 * This is the main detection predicate. Binds `algo` and `api`.
 */
predicate resolvedNodeCryptoCall(InvokeExpr call, string algo, string api) {
  api = "node:crypto" and
  (
    // ===========================
    // Hashing
    // ===========================

    // crypto.createHash("sha256")
    (
      call.getNumArgument() >= 1 and
      isNodeCryptoCall(call, "createHash") and
      algo = getArgValue(call, 0)
    )

    or

    // crypto.hash("sha256", data) — one-shot (Node 21.7+)
    // Improved guard: uses import tracking, not just receiver name
    (
      call.getNumArgument() >= 2 and
      isNodeCryptoCall(call, "hash") and
      algo = getArgValue(call, 0)
    )

    or

    // ===========================
    // HMAC
    // ===========================

    (
      call.getNumArgument() >= 1 and
      isNodeCryptoCall(call, "createHmac") and
      algo = "hmac-" + getArgValue(call, 0)
    )

    or

    // ===========================
    // Key Derivation Functions
    // ===========================

    (
      exists(string fn | fn = ["hkdf", "hkdfSync"] and isNodeCryptoCall(call, fn)) and
      call.getNumArgument() >= 1 and
      algo = "hkdf-" + getArgValue(call, 0)
    )

    or

    (
      exists(string fn | fn = ["pbkdf2", "pbkdf2Sync"] and isNodeCryptoCall(call, fn)) and
      call.getNumArgument() >= 5 and
      algo = "pbkdf2-" + getArgValue(call, 4)
    )

    or

    (
      exists(string fn | fn = ["scrypt", "scryptSync"] and isNodeCryptoCall(call, fn)) and
      algo = "scrypt"
    )

    or

    // ===========================
    // Symmetric Encryption
    // ===========================

    (
      exists(string fn | fn = ["createCipheriv", "createDecipheriv"] and isNodeCryptoCall(call, fn)) and
      call.getNumArgument() >= 1 and
      algo = getArgValue(call, 0)
    )

    or

    // Deprecated createCipher/createDecipher
    (
      exists(string fn | fn = ["createCipher", "createDecipher"] and isNodeCryptoCall(call, fn)) and
      call.getNumArgument() >= 1 and
      algo = getArgValue(call, 0) + " [deprecated-api]"
    )

    or

    // ===========================
    // Signing / Verification
    // ===========================

    (
      exists(string fn | fn = ["createSign", "createVerify"] and isNodeCryptoCall(call, fn)) and
      call.getNumArgument() >= 1 and
      algo = getArgValue(call, 0)
    )

    or

    // One-shot sign/verify — exclude subtle.sign/subtle.verify
    (
      exists(string fn | fn = ["sign", "verify"] and isNodeCryptoCall(call, fn)) and
      call.getNumArgument() >= 3 and
      not isSubtleCall(call) and
      (
        // When algo arg is null (EdDSA), report as "eddsa"
        (call.getArgument(0) instanceof NullLiteral and algo = "eddsa")
        or
        (not call.getArgument(0) instanceof NullLiteral and algo = getArgValue(call, 0))
      )
    )

    or

    // ===========================
    // Asymmetric Encryption (FIXED padding detection)
    // ===========================

    // publicEncrypt — default is PKCS1v15, NOT OAEP
    (
      isNodeCryptoCall(call, "publicEncrypt") and
      (
        // Explicit padding in options object
        algo = getRsaPadding(call)
        or
        // No options object or no padding property → default PKCS1v15
        (
          not exists(getRsaPadding(call)) and
          algo = "rsa-pkcs1v15"
        )
      )
    )

    or

    // privateDecrypt — default is PKCS1v15
    (
      isNodeCryptoCall(call, "privateDecrypt") and
      (
        algo = getRsaPadding(call)
        or
        (not exists(getRsaPadding(call)) and algo = "rsa-pkcs1v15")
      )
    )

    or

    // privateEncrypt — always PKCS1v15 (no OAEP option)
    (
      isNodeCryptoCall(call, "privateEncrypt") and
      algo = "rsa-pkcs1v15"
    )

    or

    // publicDecrypt — always PKCS1v15
    (
      isNodeCryptoCall(call, "publicDecrypt") and
      algo = "rsa-pkcs1v15"
    )

    or

    // ===========================
    // Key Generation
    // ===========================

    (
      exists(string fn | fn = ["generateKeyPair", "generateKeyPairSync"] and isNodeCryptoCall(call, fn)) and
      call.getNumArgument() >= 1 and
      algo = "keygen-" + getArgValue(call, 0)
    )

    or

    (
      exists(string fn | fn = ["generateKey", "generateKeySync"] and isNodeCryptoCall(call, fn)) and
      call.getNumArgument() >= 1 and
      not isSubtleCall(call) and
      algo = "keygen-" + getArgValue(call, 0)
    )

    or

    // ===========================
    // Diffie-Hellman
    // ===========================

    (
      isNodeCryptoCall(call, "createDiffieHellman") and
      algo = "dh"
    )

    or

    (
      exists(string fn | fn = ["createDiffieHellmanGroup", "getDiffieHellman"] and isNodeCryptoCall(call, fn)) and
      call.getNumArgument() >= 1 and
      algo = "dh-" + getArgValue(call, 0)
    )

    or

    (
      call.getNumArgument() >= 1 and
      isNodeCryptoCall(call, "createECDH") and
      algo = "ecdh-" + getArgValue(call, 0)
    )

    or

    (
      isNodeCryptoCall(call, "diffieHellman") and
      algo = "dh"
    )

    or

    // ===========================
    // Key Import
    // ===========================

    (
      isNodeCryptoCall(call, "createSecretKey") and
      algo = "secret-key-import"
    )

    or

    (
      exists(string fn | fn = ["createPublicKey", "createPrivateKey"] and isNodeCryptoCall(call, fn)) and
      algo = "asymmetric-key-import"
    )

    or

    // ===========================
    // Random Number Generation
    // ===========================

    (
      isNodeCryptoCall(call, "randomBytes") and
      algo = "csprng-randomBytes"
    )

    or

    (
      exists(string fn | fn = ["randomFill", "randomFillSync"] and isNodeCryptoCall(call, fn)) and
      algo = "csprng-randomFill"
    )

    or

    (
      isNodeCryptoCall(call, "randomInt") and
      algo = "csprng-randomInt"
    )

    or

    // ===========================
    // Certificates
    // ===========================

    (
      call instanceof NewExpr and
      call.(NewExpr).getCalleeName() = "X509Certificate" and
      algo = "x509-certificate"
    )

    or

    (
      call.getCalleeName() = ["exportChallenge", "exportPublicKey", "verifySpkac"] and
      algo = "spkac-certificate"
    )
  )
}

/**
 * Set of node:crypto function names that take an algorithm argument.
 * Used to determine which unresolved calls are worth reporting.
 */
private predicate cryptoFunctionWithAlgoArg(string functionName) {
  functionName in [
    "createHash", "hash", "createHmac", "hkdf", "hkdfSync",
    "pbkdf2", "pbkdf2Sync", "createCipheriv", "createDecipheriv",
    "createCipher", "createDecipher", "createSign", "createVerify",
    "sign", "verify",
    "generateKeyPair", "generateKeyPairSync", "generateKey", "generateKeySync",
    "createDiffieHellmanGroup", "getDiffieHellman", "createECDH"
  ]
}

/**
 * Holds for calls that match the node:crypto candidate set but whose algorithm
 * could NOT be resolved. Reported as "unresolved" so the inventory is not silently
 * incomplete.
 *
 * Handles both normal calls and aliased/renamed calls by checking against
 * all possible original function names.
 */
predicate unresolvedNodeCryptoCall(InvokeExpr call, string algo, string api) {
  api = "node:crypto" and
  algo = "unresolved" and
  isCandidateNodeCryptoCall(call) and
  // Must be a crypto call for a function that takes an algorithm argument
  exists(string originalName |
    cryptoFunctionWithAlgoArg(originalName) and
    isNodeCryptoCall(call, originalName)
  ) and
  // The resolved set does NOT contain this call
  not resolvedNodeCryptoCall(call, _, _)
}

from InvokeExpr call, string algo, string api
where
  resolvedNodeCryptoCall(call, algo, api)
  or
  unresolvedNodeCryptoCall(call, algo, api)
select call, "algo=" + algo + ", api=" + api
