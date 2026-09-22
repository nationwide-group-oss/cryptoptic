/**
 * @name Crypto inventory — WebCrypto / SubtleCrypto (JavaScript/TypeScript)
 * @description Inventory of WebCrypto API usage with algorithm detection.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/javascript-cbom-webcrypto
 * @tags security
 */

import javascript
import lib.CryptoCommon

from InvokeExpr call, string algo, string api
where
  (
    // ===========================
    // subtle.digest
    // ===========================
    (
      call.getCalleeName() = "digest" and
      call.getNumArgument() >= 1 and
      isSubtleCall(call) and
      algo = getWebCryptoAlgoNameFull(call, 0).toLowerCase() and
      api = webCryptoApi(call)
    )

    or

    // ===========================
    // subtle.encrypt / subtle.decrypt
    // ===========================
    (
      call.getCalleeName() = ["encrypt", "decrypt"] and
      call.getNumArgument() >= 2 and
      isSubtleCall(call) and
      algo = getWebCryptoAlgoNameFull(call, 0).toLowerCase() and
      api = webCryptoApi(call)
    )

    or

    // ===========================
    // subtle.sign / subtle.verify
    // ===========================
    (
      call.getCalleeName() = ["sign", "verify"] and
      call.getNumArgument() >= 2 and
      isSubtleCall(call) and
      algo = getWebCryptoAlgoNameFull(call, 0).toLowerCase() and
      api = webCryptoApi(call)
    )

    or

    // ===========================
    // subtle.generateKey
    // ===========================
    (
      call.getCalleeName() = "generateKey" and
      call.getNumArgument() >= 1 and
      isSubtleCall(call) and
      algo = "keygen-" + getWebCryptoAlgoNameFull(call, 0).toLowerCase() and
      api = webCryptoApi(call)
    )

    or

    // ===========================
    // subtle.deriveKey / subtle.deriveBits
    // ===========================
    (
      call.getCalleeName() = ["deriveKey", "deriveBits"] and
      call.getNumArgument() >= 1 and
      isSubtleCall(call) and
      algo = "derive-" + getWebCryptoAlgoNameFull(call, 0).toLowerCase() and
      api = webCryptoApi(call)
    )

    or

    // ===========================
    // subtle.importKey (algo at arg index 2)
    // ===========================
    (
      call.getCalleeName() = "importKey" and
      call.getNumArgument() >= 3 and
      isSubtleCall(call) and
      algo = "import-" + getWebCryptoAlgoNameFull(call, 2).toLowerCase() and
      api = webCryptoApi(call)
    )

    or

    // ===========================
    // subtle.exportKey
    // ===========================
    (
      call.getCalleeName() = "exportKey" and
      isSubtleCall(call) and
      api = webCryptoApi(call) and
      algo = "key-export"
    )

    or

    // ===========================
    // subtle.wrapKey (algo at arg index 3)
    // ===========================
    (
      call.getCalleeName() = "wrapKey" and
      call.getNumArgument() >= 4 and
      isSubtleCall(call) and
      algo = "wrap-" + getWebCryptoAlgoNameFull(call, 3).toLowerCase() and
      api = webCryptoApi(call)
    )

    or

    // ===========================
    // subtle.unwrapKey (algo at arg index 3)
    // ===========================
    (
      call.getCalleeName() = "unwrapKey" and
      call.getNumArgument() >= 4 and
      isSubtleCall(call) and
      algo = "unwrap-" + getWebCryptoAlgoNameFull(call, 3).toLowerCase() and
      api = webCryptoApi(call)
    )

    or

    // ===========================
    // crypto.getRandomValues / crypto.randomUUID
    // ===========================
    (
      call.getCalleeName() = "getRandomValues" and
      api = webCryptoApi(call) and
      algo = "csprng-getRandomValues"
    )

    or

    (
      call.getCalleeName() = "randomUUID" and
      api = webCryptoApi(call) and
      algo = "csprng-randomUUID"
    )

    or

    // ===========================
    // Unresolved subtle.* calls
    // ===========================
    (
      call.getCalleeName() = ["digest", "encrypt", "decrypt", "sign", "verify",
                               "generateKey", "deriveKey", "deriveBits"] and
      call.getNumArgument() >= 1 and
      isSubtleCall(call) and
      not exists(getWebCryptoAlgoNameFull(call, 0)) and
      algo = "unresolved" and
      api = webCryptoApi(call)
    )

    or

    (
      call.getCalleeName() = "importKey" and
      call.getNumArgument() >= 3 and
      isSubtleCall(call) and
      not exists(getWebCryptoAlgoNameFull(call, 2)) and
      algo = "import-unresolved" and
      api = webCryptoApi(call)
    )

    or

    (
      call.getCalleeName() = ["wrapKey", "unwrapKey"] and
      call.getNumArgument() >= 4 and
      isSubtleCall(call) and
      not exists(getWebCryptoAlgoNameFull(call, 3)) and
      algo = call.getCalleeName() + "-unresolved" and
      api = webCryptoApi(call)
    )
  )
select call, "algo=" + algo + ", api=" + api
