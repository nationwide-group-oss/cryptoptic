/**
 * @name Crypto inventory — Python Standard Library (hashlib, hmac, secrets, ssl, os)
 * @description Inventory of Python standard library cryptographic usage.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/python-cbom-stdlib
 * @tags security
 */

import python
import lib.PyCryptoCommon

from Call call, string algo, string api
where
  (
    // =============================================================================
    // hashlib — Direct hash constructors: hashlib.sha256(), hashlib.md5(), etc.
    // =============================================================================
    (
      api = "hashlib" and
      exists(Attribute attr, Name mod |
        call.getFunc() = attr and
        attr.getObject() = mod and
        mod.getId() = "hashlib" and
        (
          (attr.getName() = "md5"       and algo = "md5") or
          (attr.getName() = "sha1"      and algo = "sha1") or
          (attr.getName() = "sha224"    and algo = "sha224") or
          (attr.getName() = "sha256"    and algo = "sha256") or
          (attr.getName() = "sha384"    and algo = "sha384") or
          (attr.getName() = "sha512"    and algo = "sha512") or
          (attr.getName() = "sha3_224"  and algo = "sha3-224") or
          (attr.getName() = "sha3_256"  and algo = "sha3-256") or
          (attr.getName() = "sha3_384"  and algo = "sha3-384") or
          (attr.getName() = "sha3_512"  and algo = "sha3-512") or
          (attr.getName() = "blake2b"   and algo = "blake2b") or
          (attr.getName() = "blake2s"   and algo = "blake2s") or
          (attr.getName() = "shake_128" and algo = "shake-128") or
          (attr.getName() = "shake_256" and algo = "shake-256")
        )
      )
    )

    or

    // =============================================================================
    // hashlib.new("algorithm") — string-based hash constructor (positional or keyword "name")
    // =============================================================================
    (
      api = "hashlib" and
      isAttrCall(call, "hashlib", "new") and
      (
        exists(string name |
          (
            name = resolvePositionalArg(call, 0)
            or
            // keyword: hashlib.new(name="sha256")
            (not exists(resolvePositionalArg(call, 0)) and name = resolveKeywordArg(call, "name"))
          )
        |
          (name = "md5"       and algo = "md5") or
          (name = "sha1"      and algo = "sha1") or
          (name = "sha224"    and algo = "sha224") or
          (name = "sha256"    and algo = "sha256") or
          (name = "sha384"    and algo = "sha384") or
          (name = "sha512"    and algo = "sha512") or
          (name = "sha3_224"  and algo = "sha3-224") or
          (name = "sha3_256"  and algo = "sha3-256") or
          (name = "sha3_384"  and algo = "sha3-384") or
          (name = "sha3_512"  and algo = "sha3-512") or
          (name = "blake2b"   and algo = "blake2b") or
          (name = "blake2s"   and algo = "blake2s") or
          (name = "shake_128" and algo = "shake-128") or
          (name = "shake_256" and algo = "shake-256") or
          (name = "ripemd160" and algo = "ripemd160") or
          (name = "whirlpool" and algo = "whirlpool") or
          (name = "sm3"       and algo = "sm3") or
          (name = "md4"       and algo = "md4") or
          (name = "sha512_224" and algo = "sha512-224") or
          (name = "sha512_256" and algo = "sha512-256") or
          (name = "mdc2"      and algo = "mdc2") or
          (name = "md5-sha1"  and algo = "md5-sha1") or
          // Unrecognized algorithm name
          (
            not name = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                        "sha3_224", "sha3_256", "sha3_384", "sha3_512",
                        "blake2b", "blake2s", "shake_128", "shake_256",
                        "ripemd160", "whirlpool", "sm3", "md4",
                        "sha512_224", "sha512_256", "mdc2", "md5-sha1"] and
            algo = "unresolved"
          )
        )
        or
        // Neither positional nor keyword resolved
        (
          not exists(resolvePositionalArg(call, 0)) and
          not exists(resolveKeywordArg(call, "name")) and
          algo = "unresolved"
        )
      )
    )

    or

    // =============================================================================
    // hashlib.pbkdf2_hmac("hash", password, salt, iterations)
    // =============================================================================
    (
      api = "hashlib" and
      isAttrCall(call, "hashlib", "pbkdf2_hmac") and
      (
        exists(string h | h = resolvePositionalArg(call, 0) |
          algo = "pbkdf2-hmac-" + h
        )
        or
        (
          not exists(resolvePositionalArg(call, 0)) and
          algo = "unresolved"
        )
      )
    )

    or

    // =============================================================================
    // hashlib.file_digest(file, "algorithm") — Python 3.11+
    // =============================================================================
    (
      api = "hashlib" and
      isAttrCall(call, "hashlib", "file_digest") and
      (
        exists(string h | h = resolvePositionalArg(call, 1) |
          algo = "file-digest-" + h
        )
        or
        (
          not exists(resolvePositionalArg(call, 1)) and
          algo = "unresolved"
        )
      )
    )

    or

    // =============================================================================
    // hmac.new(key, msg, digestmod) / hmac.digest(key, msg, digest)
    // =============================================================================
    (
      api = "hmac" and
      exists(Attribute attr, Name mod |
        call.getFunc() = attr and
        attr.getObject() = mod and
        mod.getId() = "hmac" and
        attr.getName() = ["new", "digest"]
      ) and
      (
        // digestmod/digest as keyword — Attribute reference: hashlib.sha256
        exists(string kwName | kwName = ["digestmod", "digest"] |
          algo = "hmac-" + getKeywordAttrRefName(call, kwName).toLowerCase()
        )
        or
        // digestmod/digest as keyword — string literal: "sha256"
        exists(string kwName | kwName = ["digestmod", "digest"] |
          algo = "hmac-" + resolveKeywordArg(call, kwName)
        )
        or
        // digestmod as positional arg 2 — Attribute reference
        (
          not exists(string kwName | kwName = ["digestmod", "digest"] |
            exists(getKeywordAttrRefName(call, kwName)) or
            exists(getKeywordString(call, kwName))
          ) and
          (
            algo = "hmac-" + getPositionalAttrName(call, 2).toLowerCase()
            or
            algo = "hmac-" + resolvePositionalArg(call, 2)
            or
            // Positional arg 2 is a Name reference (from hashlib import sha256)
            (
              not exists(getPositionalAttrName(call, 2)) and
              not exists(resolvePositionalArg(call, 2)) and
              exists(Name digestName |
                call.getPositionalArg(2) = digestName and
                algo = "hmac-" + digestName.getId().toLowerCase()
              )
            )
            or
            // Can't resolve digestmod
            (
              not exists(getPositionalAttrName(call, 2)) and
              not exists(resolvePositionalArg(call, 2)) and
              not call.getPositionalArg(2) instanceof Name and
              algo = "unresolved"
            )
          )
        )
      )
    )

    or

    // =============================================================================
    // hmac.HMAC(key, msg, digestmod) — class-based API (Python 3.4+)
    // =============================================================================
    (
      api = "hmac" and
      isAttrCall(call, "hmac", "HMAC") and
      (
        exists(string kwName | kwName = ["digestmod", "digest"] |
          algo = "hmac-" + getKeywordAttrRefName(call, kwName).toLowerCase()
        )
        or
        exists(string kwName | kwName = ["digestmod", "digest"] |
          algo = "hmac-" + resolveKeywordArg(call, kwName)
        )
        or
        (
          not exists(string kwName | kwName = ["digestmod", "digest"] |
            exists(getKeywordAttrRefName(call, kwName)) or
            exists(getKeywordString(call, kwName))
          ) and
          (
            algo = "hmac-" + getPositionalAttrName(call, 2).toLowerCase()
            or
            algo = "hmac-" + resolvePositionalArg(call, 2)
            or
            (
              not exists(getPositionalAttrName(call, 2)) and
              not exists(resolvePositionalArg(call, 2)) and
              exists(Name digestName |
                call.getPositionalArg(2) = digestName and
                algo = "hmac-" + digestName.getId().toLowerCase()
              )
            )
            or
            (
              not exists(getPositionalAttrName(call, 2)) and
              not exists(resolvePositionalArg(call, 2)) and
              not call.getPositionalArg(2) instanceof Name and
              algo = "unresolved"
            )
          )
        )
      )
    )

    or

    // =============================================================================
    // hmac.compare_digest(a, b) — constant-time comparison
    // =============================================================================
    (
      api = "hmac" and
      isAttrCall(call, "hmac", "compare_digest") and
      algo = "hmac-compare-digest"
    )

    or

    // =============================================================================
    // secrets module — CSPRNG
    // =============================================================================
    (
      api = "secrets" and
      exists(Attribute attr, Name mod |
        call.getFunc() = attr and
        attr.getObject() = mod and
        mod.getId() = "secrets" and
        (
          (attr.getName() = "token_bytes"   and algo = "csprng-token-bytes") or
          (attr.getName() = "token_hex"     and algo = "csprng-token-hex") or
          (attr.getName() = "token_urlsafe" and algo = "csprng-token-urlsafe") or
          (attr.getName() = "randbits"      and algo = "csprng-randbits") or
          (attr.getName() = "choice"        and algo = "csprng-choice") or
          (attr.getName() = "SystemRandom"  and algo = "csprng-system-random")
        )
      )
    )

    or

    // =============================================================================
    // os.urandom(n) — random bytes
    // =============================================================================
    (
      api = "os" and
      isAttrCall(call, "os", "urandom") and
      algo = "csprng-urandom"
    )

    or

    // =============================================================================
    // ssl module — TLS
    // =============================================================================
    (
      api = "ssl" and
      exists(Attribute attr, Name mod |
        call.getFunc() = attr and
        attr.getObject() = mod and
        mod.getId() = "ssl" and
        (
          (attr.getName() = "SSLContext"             and algo = "tls-context") or
          (attr.getName() = "create_default_context" and algo = "tls-default-context") or
          (attr.getName() = "wrap_socket"            and algo = "tls-wrap-socket") or
          (attr.getName() = "RAND_bytes"             and algo = "ssl-rand-bytes") or
          (attr.getName() = "RAND_pseudo_bytes"      and algo = "ssl-rand-pseudo-bytes")
        )
      )
    )

    or

    // ssl context instance methods: context.wrap_socket(), context.load_cert_chain()
    (
      api = "ssl" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "wrap_socket"      and algo = "tls-wrap-socket") or
          (attr.getName() = "load_cert_chain"  and algo = "tls-load-cert-chain") or
          (attr.getName() = "load_verify_locations" and algo = "tls-load-verify-locations") or
          (attr.getName() = "set_ciphers"      and algo = "tls-set-ciphers") or
          (attr.getName() = "load_default_certs" and algo = "tls-load-default-certs") or
          (attr.getName() = "set_alpn_protocols" and algo = "tls-set-alpn")
        ) and
        // Guard: receiver toString mentions ssl/context/SSLContext
        (
          attr.getObject().toString().matches("%ssl%") or
          attr.getObject().toString().matches("%context%") or
          attr.getObject().toString().matches("%ctx%")
        )
      )
    )

    or

    // =============================================================================
    // ssl module — additional utility functions
    // =============================================================================
    (
      api = "ssl" and
      exists(Attribute attr, Name mod |
        call.getFunc() = attr and
        attr.getObject() = mod and
        mod.getId() = "ssl" and
        (
          (attr.getName() = "get_default_verify_paths" and algo = "ssl-default-verify-paths") or
          (attr.getName() = "enum_certificates"        and algo = "ssl-enum-certificates") or
          (attr.getName() = "enum_crls"                and algo = "ssl-enum-crls") or
          (attr.getName() = "match_hostname"           and algo = "ssl-match-hostname") or
          (attr.getName() = "cert_time_to_seconds"     and algo = "ssl-cert-time") or
          (attr.getName() = "get_server_certificate"   and algo = "ssl-get-server-cert") or
          (attr.getName() = "DER_cert_to_PEM_cert"     and algo = "ssl-der-to-pem") or
          (attr.getName() = "PEM_cert_to_DER_cert"     and algo = "ssl-pem-to-der")
        )
      )
    )

    or

    // =============================================================================
    // hashlib — algorithms_guaranteed / algorithms_available (attribute access,
    // not calls, but detect usage of hash objects via .hexdigest() / .digest())
    // =============================================================================
    (
      api = "hashlib" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%hashlib%") and
        (
          (attr.getName() = "copy" and algo = "hash-copy")
        )
      )
    )

    or

    // =============================================================================
    // crypt module (Unix) — crypt.crypt(), crypt.mksalt() [deprecated in 3.13]
    // =============================================================================
    (
      api = "crypt" and
      exists(Attribute attr, Name mod |
        call.getFunc() = attr and
        attr.getObject() = mod and
        mod.getId() = "crypt" and
        (
          (attr.getName() = "crypt"  and algo = "unix-crypt") or
          (attr.getName() = "mksalt" and algo = "unix-mksalt")
        )
      )
    )
  )
select call, "algo=" + algo + ", api=" + api
