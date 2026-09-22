/**
 * @name Crypto inventory — PyCryptodome / PyCrypto (Python)
 * @description Inventory of PyCryptodome and PyCrypto library usage including
 *              Cipher, Hash, PublicKey, Signature, and KDF modules.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/python-cbom-pycryptodome
 * @tags security
 */

import python
import lib.PyCryptoCommon

/**
 * Maps PyCryptodome MODE_* constants to mode names.
 * Handles positional arg 1 as Attribute, keyword `mode=`, and bare Name after from-import.
 */
string pycryptodomeMode(Call call) {
  // Positional arg 1 as Attribute: AES.MODE_GCM
  exists(Attribute modeAttr |
    call.getPositionalArg(1) = modeAttr and
    (
      (modeAttr.getName() = "MODE_GCM"     and result = "gcm") or
      (modeAttr.getName() = "MODE_CBC"     and result = "cbc") or
      (modeAttr.getName() = "MODE_CTR"     and result = "ctr") or
      (modeAttr.getName() = "MODE_ECB"     and result = "ecb") or
      (modeAttr.getName() = "MODE_CFB"     and result = "cfb") or
      (modeAttr.getName() = "MODE_OFB"     and result = "ofb") or
      (modeAttr.getName() = "MODE_CCM"     and result = "ccm") or
      (modeAttr.getName() = "MODE_EAX"     and result = "eax") or
      (modeAttr.getName() = "MODE_SIV"     and result = "siv") or
      (modeAttr.getName() = "MODE_OCB"     and result = "ocb") or
      (modeAttr.getName() = "MODE_OPENPGP" and result = "openpgp")
    )
  )
  or
  // Positional arg 1 as bare Name (from Crypto.Cipher.AES import MODE_GCM)
  exists(Name modeName |
    call.getPositionalArg(1) = modeName and
    (
      (modeName.getId() = "MODE_GCM"     and result = "gcm") or
      (modeName.getId() = "MODE_CBC"     and result = "cbc") or
      (modeName.getId() = "MODE_CTR"     and result = "ctr") or
      (modeName.getId() = "MODE_ECB"     and result = "ecb") or
      (modeName.getId() = "MODE_CFB"     and result = "cfb") or
      (modeName.getId() = "MODE_OFB"     and result = "ofb") or
      (modeName.getId() = "MODE_CCM"     and result = "ccm") or
      (modeName.getId() = "MODE_EAX"     and result = "eax") or
      (modeName.getId() = "MODE_SIV"     and result = "siv") or
      (modeName.getId() = "MODE_OCB"     and result = "ocb") or
      (modeName.getId() = "MODE_OPENPGP" and result = "openpgp")
    )
  )
  or
  // Keyword arg: mode=AES.MODE_GCM
  exists(Keyword kw, Attribute modeAttr |
    call.getAKeyword() = kw and
    kw.getArg() = "mode" and
    kw.getValue() = modeAttr and
    (
      (modeAttr.getName() = "MODE_GCM"     and result = "gcm") or
      (modeAttr.getName() = "MODE_CBC"     and result = "cbc") or
      (modeAttr.getName() = "MODE_CTR"     and result = "ctr") or
      (modeAttr.getName() = "MODE_ECB"     and result = "ecb") or
      (modeAttr.getName() = "MODE_CFB"     and result = "cfb") or
      (modeAttr.getName() = "MODE_OFB"     and result = "ofb") or
      (modeAttr.getName() = "MODE_CCM"     and result = "ccm") or
      (modeAttr.getName() = "MODE_EAX"     and result = "eax") or
      (modeAttr.getName() = "MODE_SIV"     and result = "siv") or
      (modeAttr.getName() = "MODE_OCB"     and result = "ocb") or
      (modeAttr.getName() = "MODE_OPENPGP" and result = "openpgp")
    )
  )
  or
  // Keyword arg as bare Name: mode=MODE_GCM
  exists(Keyword kw, Name modeName |
    call.getAKeyword() = kw and
    kw.getArg() = "mode" and
    kw.getValue() = modeName and
    (
      (modeName.getId() = "MODE_GCM"     and result = "gcm") or
      (modeName.getId() = "MODE_CBC"     and result = "cbc") or
      (modeName.getId() = "MODE_CTR"     and result = "ctr") or
      (modeName.getId() = "MODE_ECB"     and result = "ecb") or
      (modeName.getId() = "MODE_CFB"     and result = "cfb") or
      (modeName.getId() = "MODE_OFB"     and result = "ofb") or
      (modeName.getId() = "MODE_CCM"     and result = "ccm") or
      (modeName.getId() = "MODE_EAX"     and result = "eax") or
      (modeName.getId() = "MODE_SIV"     and result = "siv") or
      (modeName.getId() = "MODE_OCB"     and result = "ocb") or
      (modeName.getId() = "MODE_OPENPGP" and result = "openpgp")
    )
  )
}

from Call call, string algo, string api
where
  (
    // =============================================================================
    // Cipher modules — AES.new(key, AES.MODE_GCM, nonce=nonce)
    // Covers: Crypto.Cipher.X and Cryptodome.Cipher.X
    // =============================================================================

    // AES
    (
      isAttrCall(call, "AES", "new") and
      (
        exists(string mode | mode = pycryptodomeMode(call) |
          algo = "aes-" + mode
        )
        or
        (not exists(pycryptodomeMode(call)) and algo = "unresolved")
      ) and
      api = "PyCryptodome"
    )

    or

    // DES
    (
      isAttrCall(call, "DES", "new") and
      (
        exists(string mode | mode = pycryptodomeMode(call) |
          algo = "des-" + mode
        )
        or
        (not exists(pycryptodomeMode(call)) and algo = "unresolved")
      ) and
      api = "PyCryptodome"
    )

    or

    // DES3 (Triple DES)
    (
      isAttrCall(call, "DES3", "new") and
      (
        exists(string mode | mode = pycryptodomeMode(call) |
          algo = "3des-" + mode
        )
        or
        (not exists(pycryptodomeMode(call)) and algo = "unresolved")
      ) and
      api = "PyCryptodome"
    )

    or

    // Blowfish
    (
      isAttrCall(call, "Blowfish", "new") and
      (
        exists(string mode | mode = pycryptodomeMode(call) |
          algo = "blowfish-" + mode
        )
        or
        (not exists(pycryptodomeMode(call)) and algo = "unresolved")
      ) and
      api = "PyCryptodome"
    )

    or

    // CAST
    (
      isAttrCall(call, "CAST", "new") and algo = "cast" and api = "PyCryptodome"
    )

    or

    // ARC2
    (
      isAttrCall(call, "ARC2", "new") and algo = "arc2" and api = "PyCryptodome"
    )

    or

    // Stream ciphers
    (isAttrCall(call, "ARC4", "new") and algo = "arc4" and api = "PyCryptodome") or
    (isAttrCall(call, "ChaCha20", "new") and algo = "chacha20" and api = "PyCryptodome") or
    (isAttrCall(call, "Salsa20", "new") and algo = "salsa20" and api = "PyCryptodome") or
    (isAttrCall(call, "ChaCha20_Poly1305", "new") and algo = "chacha20-poly1305" and api = "PyCryptodome")

    or

    // =============================================================================
    // Hash modules — SHA256.new(data), MD5.new(data)
    // Covers: Crypto.Hash.X and Cryptodome.Hash.X
    // =============================================================================
    (isAttrCall(call, "MD2", "new") and algo = "md2" and api = "PyCryptodome") or
    (isAttrCall(call, "MD4", "new") and algo = "md4" and api = "PyCryptodome") or
    (isAttrCall(call, "MD5", "new") and algo = "md5" and api = "PyCryptodome") or
    (isAttrCall(call, "SHA1", "new") and algo = "sha1" and api = "PyCryptodome") or
    (isAttrCall(call, "SHA224", "new") and algo = "sha224" and api = "PyCryptodome") or
    (isAttrCall(call, "SHA256", "new") and algo = "sha256" and api = "PyCryptodome") or
    (isAttrCall(call, "SHA384", "new") and algo = "sha384" and api = "PyCryptodome") or
    (isAttrCall(call, "SHA512", "new") and algo = "sha512" and api = "PyCryptodome") or
    (isAttrCall(call, "SHA3_224", "new") and algo = "sha3-224" and api = "PyCryptodome") or
    (isAttrCall(call, "SHA3_256", "new") and algo = "sha3-256" and api = "PyCryptodome") or
    (isAttrCall(call, "SHA3_384", "new") and algo = "sha3-384" and api = "PyCryptodome") or
    (isAttrCall(call, "SHA3_512", "new") and algo = "sha3-512" and api = "PyCryptodome") or
    (isAttrCall(call, "BLAKE2b", "new") and algo = "blake2b" and api = "PyCryptodome") or
    (isAttrCall(call, "BLAKE2s", "new") and algo = "blake2s" and api = "PyCryptodome") or
    (isAttrCall(call, "RIPEMD160", "new") and algo = "ripemd160" and api = "PyCryptodome") or
    (isAttrCall(call, "RIPEMD", "new") and algo = "ripemd160" and api = "PyCryptodome") or
    (isAttrCall(call, "keccak", "new") and algo = "keccak" and api = "PyCryptodome") or
    (isAttrCall(call, "SHAKE128", "new") and algo = "shake-128" and api = "PyCryptodome") or
    (isAttrCall(call, "SHAKE256", "new") and algo = "shake-256" and api = "PyCryptodome") or
    (isAttrCall(call, "TurboSHAKE128", "new") and algo = "turboshake-128" and api = "PyCryptodome") or
    (isAttrCall(call, "TurboSHAKE256", "new") and algo = "turboshake-256" and api = "PyCryptodome") or
    (isAttrCall(call, "KangarooTwelve", "new") and algo = "kangaroo-twelve" and api = "PyCryptodome") or
    (isAttrCall(call, "cSHAKE128", "new") and algo = "cshake-128" and api = "PyCryptodome") or
    (isAttrCall(call, "cSHAKE256", "new") and algo = "cshake-256" and api = "PyCryptodome") or
    (isAttrCall(call, "KMAC128", "new") and algo = "kmac128" and api = "PyCryptodome") or
    (isAttrCall(call, "KMAC256", "new") and algo = "kmac256" and api = "PyCryptodome") or
    (isAttrCall(call, "TupleHash128", "new") and algo = "tuplehash128" and api = "PyCryptodome") or
    (isAttrCall(call, "TupleHash256", "new") and algo = "tuplehash256" and api = "PyCryptodome")

    or

    // =============================================================================
    // HMAC — Crypto.Hash.HMAC.new(key, msg, SHA256)
    // =============================================================================
    (
      isAttrCall(call, "HMAC", "new") and
      api = "PyCryptodome" and
      (
        // Positional arg 2 is the hash module reference (e.g. SHA256)
        exists(Name hashRef |
          call.getPositionalArg(2) = hashRef and
          algo = "hmac-" + hashRef.getId().toLowerCase()
        )
        or
        // keyword digestmod=SHA256
        exists(Keyword kw, Name hashRef |
          call.getAKeyword() = kw and
          kw.getArg() = "digestmod" and
          kw.getValue() = hashRef and
          algo = "hmac-" + hashRef.getId().toLowerCase()
        )
        or
        // Can't resolve hash
        (
          not exists(Name hashRef | call.getPositionalArg(2) = hashRef) and
          not exists(Keyword kw | call.getAKeyword() = kw and kw.getArg() = "digestmod") and
          algo = "unresolved"
        )
      )
    )

    or

    // =============================================================================
    // CMAC — Crypto.Hash.CMAC.new(key, msg, AES)
    // =============================================================================
    (
      isAttrCall(call, "CMAC", "new") and algo = "cmac" and api = "PyCryptodome"
    )

    or

    // =============================================================================
    // PublicKey — RSA, DSA, ECC, ElGamal
    // =============================================================================
    (isAttrCall(call, "RSA", "generate") and algo = "rsa-keygen" and api = "PyCryptodome") or
    (isAttrCall(call, "RSA", "import_key") and algo = "rsa-import" and api = "PyCryptodome") or
    (isAttrCall(call, "RSA", "importKey") and algo = "rsa-import" and api = "PyCryptodome") or
    (isAttrCall(call, "RSA", "construct") and algo = "rsa-construct" and api = "PyCryptodome") or

    (isAttrCall(call, "DSA", "generate") and algo = "dsa-keygen" and api = "PyCryptodome") or
    (isAttrCall(call, "DSA", "import_key") and algo = "dsa-import" and api = "PyCryptodome") or
    (isAttrCall(call, "DSA", "importKey") and algo = "dsa-import" and api = "PyCryptodome") or
    (isAttrCall(call, "DSA", "construct") and algo = "dsa-construct" and api = "PyCryptodome") or

    (isAttrCall(call, "ECC", "generate") and algo = "ecc-keygen" and api = "PyCryptodome") or
    (isAttrCall(call, "ECC", "import_key") and algo = "ecc-import" and api = "PyCryptodome") or
    (isAttrCall(call, "ECC", "construct") and algo = "ecc-construct" and api = "PyCryptodome") or

    (isAttrCall(call, "ElGamal", "generate") and algo = "elgamal-keygen" and api = "PyCryptodome")

    or

    // ECC with curve parameter (keyword or positional)
    (
      isAttrCall(call, "ECC", "generate") and
      api = "PyCryptodome" and
      (
        exists(string curve | curve = getKeywordString(call, "curve") |
          algo = "ecc-keygen-" + curve.toLowerCase()
        )
        or
        exists(string curve | curve = resolvePositionalArg(call, 0) |
          algo = "ecc-keygen-" + curve
        )
      )
    )

    or

    // =============================================================================
    // Signature — PKCS1_v1_5, PKCS1_PSS, DSS, eddsa
    // =============================================================================
    (isAttrCall(call, "pkcs1_15", "new") and algo = "rsa-sig-pkcs1v15" and api = "PyCryptodome") or
    (isAttrCall(call, "PKCS1_v1_5", "new") and algo = "rsa-sig-pkcs1v15" and api = "PyCryptodome") or
    (isAttrCall(call, "pss", "new") and algo = "rsa-sig-pss" and api = "PyCryptodome") or
    (isAttrCall(call, "PKCS1_PSS", "new") and algo = "rsa-sig-pss" and api = "PyCryptodome") or
    (isAttrCall(call, "DSS", "new") and algo = "dss-sig" and api = "PyCryptodome") or
    (isAttrCall(call, "eddsa", "new") and algo = "eddsa-sig" and api = "PyCryptodome")

    or

    // =============================================================================
    // PKCS1_OAEP — RSA encryption with hash algorithm extraction
    // =============================================================================
    (
      isAttrCall(call, "PKCS1_OAEP", "new") and api = "PyCryptodome" and
      (
        // hashAlgo keyword
        exists(Keyword kw, Name hashRef |
          call.getAKeyword() = kw and
          kw.getArg() = "hashAlgo" and
          kw.getValue() = hashRef and
          algo = "rsa-oaep-" + hashRef.getId().toLowerCase()
        )
        or
        // hashAlgo as positional arg 1
        exists(Name hashRef |
          call.getPositionalArg(1) = hashRef and
          algo = "rsa-oaep-" + hashRef.getId().toLowerCase()
        )
        or
        // No hashAlgo resolved
        (
          not exists(Keyword kw | call.getAKeyword() = kw and kw.getArg() = "hashAlgo") and
          not call.getPositionalArg(1) instanceof Name and
          algo = "rsa-oaep"
        )
      )
    )

    or

    // =============================================================================
    // Poly1305 — Crypto.Hash.Poly1305
    // =============================================================================
    (isAttrCall(call, "Poly1305", "new") and algo = "poly1305" and api = "PyCryptodome")

    or

    // =============================================================================
    // KDF — PBKDF2, scrypt, HKDF, bcrypt_kdf
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%KDF%") and
        (
          (attr.getName() = "PBKDF2" and algo = "pbkdf2") or
          (attr.getName() = "scrypt" and algo = "scrypt") or
          (attr.getName() = "bcrypt" and algo = "bcrypt-kdf") or
          (attr.getName() = "bcrypt_check" and algo = "bcrypt-check") or
          (attr.getName() = "HKDF"   and algo = "hkdf") or
          (attr.getName() = "SP800_108_Counter" and algo = "sp800-108-counter")
        )
      ) and
      api = "PyCryptodome"
    )

    or

    // Direct function calls
    (
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "PBKDF2" and algo = "pbkdf2") or
          (fn.getId() = "scrypt" and algo = "scrypt") or
          (fn.getId() = "HKDF"   and algo = "hkdf") or
          (fn.getId() = "SP800_108_Counter" and algo = "sp800-108-counter")
        )
      ) and
      api = "PyCryptodome"
    )

    or

    // =============================================================================
    // Random — Crypto.Random
    // =============================================================================
    (
      isAttrCall(call, "Random", "get_random_bytes") and
      algo = "csprng-random" and api = "PyCryptodome"
    )

    or

    // Direct import: from Crypto.Random import get_random_bytes
    (
      exists(Name fn |
        call.getFunc() = fn and
        fn.getId() = "get_random_bytes"
      ) and
      // Guard: file must reference Crypto/Cryptodome modules
      (
        call.getLocation().getFile().toString().matches("%Crypto%") or
        call.getLocation().getFile().toString().matches("%Cryptodome%") or
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          (
            a.getObject().(Name).getId() = ["AES", "DES", "DES3", "RSA", "ECC", "DSA",
              "SHA256", "SHA384", "SHA512", "HMAC", "CMAC", "Random"] or
            a.getObject().(Name).getId().matches("Crypto%")
          )
        )
      ) and
      algo = "csprng-random" and api = "PyCryptodome"
    )

    or

    // =============================================================================
    // Crypto.Util.Padding — pad(data, block_size, style), unpad(data, block_size, style)
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%Padding%") and
        (
          (attr.getName() = "pad"   and algo = "padding-pad") or
          (attr.getName() = "unpad" and algo = "padding-unpad")
        )
      ) and
      api = "PyCryptodome"
    )

    or

    // Direct imports: from Crypto.Util.Padding import pad, unpad
    (
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "pad"   and algo = "padding-pad") or
          (fn.getId() = "unpad" and algo = "padding-unpad")
        )
      ) and
      (
        call.getLocation().getFile().toString().matches("%Crypto%") or
        call.getLocation().getFile().toString().matches("%Cryptodome%") or
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          (
            a.getObject().(Name).getId().matches("Crypto%") or
            a.getObject().(Name).getId() = ["AES", "DES", "DES3"]
          )
        )
      ) and
      api = "PyCryptodome"
    )

    or

    // =============================================================================
    // Crypto.Util.Counter — Counter.new(nbits, ...)
    // =============================================================================
    (
      isAttrCall(call, "Counter", "new") and algo = "counter" and api = "PyCryptodome"
    )

    or

    // =============================================================================
    // Crypto.Protocol.SecretSharing — Shamir.split, Shamir.combine
    // =============================================================================
    (
      isAttrCall(call, "Shamir", "split")   and algo = "shamir-split"   and api = "PyCryptodome"
    ) or
    (
      isAttrCall(call, "Shamir", "combine") and algo = "shamir-combine" and api = "PyCryptodome"
    )

    or

    // =============================================================================
    // Crypto.Cipher.PKCS1_v1_5 — RSA encryption (distinct from Signature module)
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%PKCS1_v1_5%") and
        (
          (attr.getName() = "new"     and algo = "rsa-enc-pkcs1v15") or
          (attr.getName() = "encrypt" and algo = "rsa-enc-pkcs1v15-encrypt") or
          (attr.getName() = "decrypt" and algo = "rsa-enc-pkcs1v15-decrypt")
        )
      ) and
      api = "PyCryptodome"
    )

    or

    // =============================================================================
    // Crypto.IO.PEM — PEM encoding/decoding
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%PEM%") and
        (
          (attr.getName() = "encode" and algo = "pem-encode") or
          (attr.getName() = "decode" and algo = "pem-decode")
        )
      ) and
      api = "PyCryptodome"
    )

    or

    // =============================================================================
    // Crypto.IO.PKCS8 — PKCS#8 key wrapping
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%PKCS8%") and
        (
          (attr.getName() = "wrap"   and algo = "pkcs8-wrap") or
          (attr.getName() = "unwrap" and algo = "pkcs8-unwrap")
        )
      ) and
      api = "PyCryptodome"
    )

    or

    // =============================================================================
    // Crypto.Util.strxor — constant-time XOR
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%strxor%") and
        (
          (attr.getName() = "strxor"   and algo = "strxor") or
          (attr.getName() = "strxor_c" and algo = "strxor-constant")
        )
      ) and
      api = "PyCryptodome"
    ) or
    (
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "strxor"   and algo = "strxor") or
          (fn.getId() = "strxor_c" and algo = "strxor-constant")
        )
      ) and
      exists(Attribute a |
        a.getLocation().getFile() = call.getLocation().getFile() and
        a.getObject().(Name).getId().matches("Crypto%")
      ) and
      api = "PyCryptodome"
    )

    or

    // =============================================================================
    // Crypto.Util.number — number theory utilities for crypto
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%number%") and
        (
          (attr.getName() = "getPrime"        and algo = "get-prime") or
          (attr.getName() = "getStrongPrime"  and algo = "get-strong-prime") or
          (attr.getName() = "isPrime"         and algo = "is-prime") or
          (attr.getName() = "getRandomNBitInteger" and algo = "random-nbit-int") or
          (attr.getName() = "getRandomInteger" and algo = "random-integer") or
          (attr.getName() = "getRandomRange"  and algo = "random-range")
        )
      ) and
      (
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          a.getObject().(Name).getId().matches("Crypto%")
        ) or
        call.getLocation().getFile().toString().matches("%Crypto%")
      ) and
      api = "PyCryptodome"
    )
  )
select call, "algo=" + algo + ", api=" + api
