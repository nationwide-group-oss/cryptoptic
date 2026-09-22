/**
 * @name Crypto inventory — CryptoJS / crypto-es (JavaScript/TypeScript)
 * @description Inventory of CryptoJS and crypto-es library usage.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/javascript-cbom-cryptojs
 * @tags security
 */

import javascript
import lib.CryptoCommon

/**
 * Gets the name of the receiver in a chained call like `obj.Cipher.method(...)`.
 * For `CryptoJS.AES.encrypt(...)` returns "AES".
 */
string getCjsReceiverName(InvokeExpr call) {
  exists(PropAccess callee |
    callee = call.getCallee() and
    result = callee.getBase().(PropAccess).getPropertyName()
  )
}

/**
 * Determines the API attribution: "CryptoJS" or "crypto-es" based on imports.
 */
string cjsApi(InvokeExpr call) {
  if fileImportsModule(call, "crypto-es")
  then result = "crypto-es"
  else result = "CryptoJS"
}

/**
 * Holds if the callee name is a CryptoJS-relevant function.
 */
predicate isCandidateCjsCall(InvokeExpr call) {
  call.getCalleeName() in [
    "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3", "RIPEMD160",
    "HmacMD5", "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512",
    "HmacSHA3", "HmacRIPEMD160",
    "encrypt", "decrypt",
    "PBKDF2", "EvpKDF",
    "create", "createEncryptor", "createDecryptor",
    "random"
  ]
}

/**
 * Maps the receiver of a progressive create/createEncryptor/createDecryptor call
 * to its algorithm label.
 */
string progressiveAlgo(InvokeExpr call) {
  exists(string r | r = getCjsReceiverName(call) |
    (r = "MD5"       and result = "progressive-md5") or
    (r = "SHA1"      and result = "progressive-sha1") or
    (r = "SHA224"    and result = "progressive-sha224") or
    (r = "SHA256"    and result = "progressive-sha256") or
    (r = "SHA384"    and result = "progressive-sha384") or
    (r = "SHA512"    and result = "progressive-sha512") or
    (r = "SHA3"      and result = "progressive-sha3") or
    (r = "RIPEMD160" and result = "progressive-ripemd160") or
    (r = "AES"       and result = "progressive-aes") or
    (r = "DES"       and result = "progressive-des") or
    (r = "TripleDES" and result = "progressive-3des") or
    (r = "Rabbit"    and result = "progressive-rabbit") or
    (r = "RC4"       and result = "progressive-rc4") or
    (r = "RC4Drop"   and result = "progressive-rc4drop") or
    (r = "Blowfish"  and result = "progressive-blowfish")
  )
}

/**
 * Maps the receiver of an encrypt/decrypt call to its block cipher base name.
 */
string blockCipherBase(InvokeExpr call) {
  exists(string r | r = getCjsReceiverName(call) |
    (r = "AES"       and result = "aes") or
    (r = "DES"       and result = "des") or
    (r = "TripleDES" and result = "3des") or
    (r = "Blowfish"  and result = "blowfish")
  )
}

from InvokeExpr call, string algo, string api
where
  isCandidateCjsCall(call) and
  api = cjsApi(call) and
  (
    // ===========================
    // Hash Functions
    // ===========================
    (call.getCalleeName() = "MD5" and algo = "md5") or
    (call.getCalleeName() = "SHA1" and algo = "sha1") or
    (call.getCalleeName() = "SHA224" and algo = "sha224") or
    (call.getCalleeName() = "SHA256" and algo = "sha256") or
    (call.getCalleeName() = "SHA384" and algo = "sha384") or
    (call.getCalleeName() = "SHA512" and algo = "sha512") or
    (call.getCalleeName() = "RIPEMD160" and algo = "ripemd160") or
    (
      call.getCalleeName() = "SHA3" and
      (
        exists(NumberLiteral bits |
          bits = call.getArgument(1).(ObjectExpr).getPropertyByName("outputLength").getInit() and
          algo = "sha3-" + bits.getValue()
        )
        or
        (
          not exists(
            call.getArgument(1).(ObjectExpr).getPropertyByName("outputLength").getInit().(NumberLiteral)
          ) and
          algo = "sha3"
        )
      )
    )

    or

    // ===========================
    // HMAC Functions
    // ===========================
    (call.getCalleeName() = "HmacMD5" and algo = "hmac-md5") or
    (call.getCalleeName() = "HmacSHA1" and algo = "hmac-sha1") or
    (call.getCalleeName() = "HmacSHA224" and algo = "hmac-sha224") or
    (call.getCalleeName() = "HmacSHA256" and algo = "hmac-sha256") or
    (call.getCalleeName() = "HmacSHA384" and algo = "hmac-sha384") or
    (call.getCalleeName() = "HmacSHA512" and algo = "hmac-sha512") or
    (call.getCalleeName() = "HmacSHA3" and algo = "hmac-sha3") or
    (call.getCalleeName() = "HmacRIPEMD160" and algo = "hmac-ripemd160")

    or

    // ===========================
    // Cipher Functions
    // ===========================
    (
      call.getCalleeName() = ["encrypt", "decrypt"] and
      (
        // Block ciphers with optional mode
        exists(string base | base = blockCipherBase(call) |
          (
            algo = base + "-" + getOptionsPropAccessName(call, 2, "mode").toLowerCase()
          )
          or
          (
            not exists(getOptionsPropAccessName(call, 2, "mode")) and
            algo = base
          )
        )
        or
        // Stream ciphers
        exists(string r | r = getCjsReceiverName(call) |
          (r = "Rabbit"  and algo = "rabbit") or
          (r = "RC4"     and algo = "rc4") or
          (r = "RC4Drop" and algo = "rc4drop")
        )
      )
    )

    or

    // ===========================
    // Key Derivation
    // ===========================
    (
      call.getCalleeName() = "PBKDF2" and
      (
        exists(string hashName |
          hashName = getOptionsPropAccessName(call, 2, "hasher") and
          algo = "pbkdf2-" + hashName.toLowerCase()
        )
        or
        (not exists(getOptionsPropAccessName(call, 2, "hasher")) and algo = "pbkdf2")
      )
    )
    or
    (
      call.getCalleeName() = "EvpKDF" and
      (
        exists(string hashName |
          hashName = getOptionsPropAccessName(call, 2, "hasher") and
          algo = "evpkdf-" + hashName.toLowerCase()
        )
        or
        (not exists(getOptionsPropAccessName(call, 2, "hasher")) and algo = "evpkdf")
      )
    )

    or

    // ===========================
    // Progressive Hashing / Cipher
    // ===========================
    (
      call.getCalleeName() = ["create", "createEncryptor", "createDecryptor"] and
      getCjsReceiverName(call) != "HMAC" and
      algo = progressiveAlgo(call)
    )

    or

    // ===========================
    // Progressive HMAC
    // ===========================
    (
      call.getCalleeName() = "create" and
      getCjsReceiverName(call) = "HMAC" and
      call.getNumArgument() >= 1 and
      exists(string hashAlgo |
        hashAlgo = call.getArgument(0).(PropAccess).getPropertyName() |
        algo = "progressive-hmac-" + hashAlgo.toLowerCase()
      )
    )
    or
    // HMAC.create with unresolvable hash argument
    (
      call.getCalleeName() = "create" and
      getCjsReceiverName(call) = "HMAC" and
      (call.getNumArgument() = 0 or not call.getArgument(0) instanceof PropAccess) and
      algo = "progressive-hmac-unresolved"
    )

    or

    // ===========================
    // Random
    // ===========================
    (
      call.getCalleeName() = "random" and
      getCjsReceiverName(call) = "WordArray" and
      algo = "csprng-random"
    )
  )
select call, "algo=" + algo + ", api=" + api
