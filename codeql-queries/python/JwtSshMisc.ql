/**
 * @name Crypto inventory — JWT, SSH, NaCl, OpenPGP & Misc (Python)
 * @description Inventory of JWT/JOSE, SSH, PyNaCl, OpenPGP, and miscellaneous
 *              crypto-consuming library usage.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/python-cbom-jwt-ssh-misc
 * @tags security
 */

import python
import lib.PyCryptoCommon

from Call call, string algo, string api
where
  (
    // =============================================================================
    // PyJWT — jwt.encode(), jwt.decode()
    // =============================================================================

    // jwt.encode(payload, key, algorithm="RS256")
    // Guarded: exclude Authlib-style calls where the first positional arg is
    // a header Dict (Authlib convention: jwt.encode({'alg': 'RS256'}, ...)).
    // Also exclude files with python-jose-specific constructs (jws/jwe) to
    // avoid double-counting — python-jose shares the same jwt.* API.
    (
      api = "PyJWT" and
      isAttrCall(call, "jwt", "encode") and
      not call.getPositionalArg(0) instanceof Dict and
      not fileUsesPythonJose(call.getLocation().getFile()) and
      (
        exists(string alg | alg = resolveKeywordArg(call, "algorithm") |
          algo = "jwt-sign-" + alg
        )
        or
        // Positional arg 2 is algorithm (PyJWT < 2.0)
        (
          not exists(resolveKeywordArg(call, "algorithm")) and
          exists(string alg | alg = resolvePositionalArg(call, 2) |
            algo = "jwt-sign-" + alg
          )
        )
        or
        // No explicit algorithm — default HS256 per RFC 7519
        (
          not exists(resolveKeywordArg(call, "algorithm")) and
          not exists(resolvePositionalArg(call, 2)) and
          algo = "jwt-sign-hs256"
        )
      )
    )

    or

    // jwt.decode(token, key, algorithms=["RS256"])
    // Guarded: exclude Authlib files and python-jose files.
    (
      api = "PyJWT" and
      isAttrCall(call, "jwt", "decode") and
      not fileUsesAuthlib(call.getLocation().getFile()) and
      not fileUsesPythonJose(call.getLocation().getFile()) and
      algo = "jwt-decode"
    )

    or

    // jwt.decode_complete(token, key, algorithms=["RS256"])
    (
      api = "PyJWT" and
      isAttrCall(call, "jwt", "decode_complete") and
      not fileUsesAuthlib(call.getLocation().getFile()) and
      not fileUsesPythonJose(call.getLocation().getFile()) and
      algo = "jwt-decode-complete"
    )

    or

    // jwt.get_unverified_header(token)
    (
      api = "PyJWT" and
      isAttrCall(call, "jwt", "get_unverified_header") and
      not fileUsesPythonJose(call.getLocation().getFile()) and
      algo = "jwt-get-unverified-header"
    )

    or

    // =============================================================================
    // PyJWT — jwt.algorithms.* (RSAAlgorithm, ECAlgorithm, etc.)
    // =============================================================================
    (
      api = "PyJWT" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%algorithms%") and
        (
          (attr.getName() = "RSAAlgorithm"     and algo = "jwt-algo-rsa") or
          (attr.getName() = "ECAlgorithm"      and algo = "jwt-algo-ec") or
          (attr.getName() = "HMACAlgorithm"    and algo = "jwt-algo-hmac") or
          (attr.getName() = "Ed25519Algorithm" and algo = "jwt-algo-ed25519") or
          (attr.getName() = "Ed448Algorithm"   and algo = "jwt-algo-ed448") or
          (attr.getName() = "OKPAlgorithm"     and algo = "jwt-algo-okp") or
          (attr.getName() = "RSAPSSAlgorithm"  and algo = "jwt-algo-rsa-pss")
        )
      )
    )

    or

    // Direct Name constructors for jwt.algorithms classes
    (
      api = "PyJWT" and
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "RSAAlgorithm"     and algo = "jwt-algo-rsa") or
          (fn.getId() = "ECAlgorithm"      and algo = "jwt-algo-ec") or
          (fn.getId() = "HMACAlgorithm"    and algo = "jwt-algo-hmac") or
          (fn.getId() = "Ed25519Algorithm" and algo = "jwt-algo-ed25519") or
          (fn.getId() = "Ed448Algorithm"   and algo = "jwt-algo-ed448") or
          (fn.getId() = "OKPAlgorithm"     and algo = "jwt-algo-okp") or
          (fn.getId() = "RSAPSSAlgorithm"  and algo = "jwt-algo-rsa-pss")
        )
      ) and
      fileImportsJwt(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // PyJWT — PyJWS (raw JWS operations)
    // =============================================================================
    (
      api = "PyJWT" and
      isConstructorCall(call, "PyJWS") and
      algo = "pyjws"
    )

    or

    // PyJWS instance methods
    (
      api = "PyJWT" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%[Pp]y[Jj][Ww][Ss]%") and
        (
          (attr.getName() = "encode" and algo = "pyjws-encode") or
          (attr.getName() = "decode" and algo = "pyjws-decode") or
          (attr.getName() = "decode_complete" and algo = "pyjws-decode-complete")
        )
      ) and
      fileImportsJwt(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // PyJWT — PyJWT class (direct instantiation)
    // =============================================================================
    (
      api = "PyJWT" and
      isConstructorCall(call, "PyJWT") and
      algo = "pyjwt-instance"
    )

    or

    // PyJWT instance methods
    (
      api = "PyJWT" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%[Pp]y[Jj][Ww][Tt]%") and
        (
          (attr.getName() = "encode" and algo = "pyjwt-encode") or
          (attr.getName() = "decode" and algo = "pyjwt-decode") or
          (attr.getName() = "decode_complete" and algo = "pyjwt-decode-complete")
        )
      ) and
      fileImportsJwt(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // PyJWT — PyJWKClient (JWKS key fetching)
    // =============================================================================
    (
      api = "PyJWT" and
      (
        isConstructorCall(call, "PyJWKClient") or
        isAttrCall(call, "jwks_client", "PyJWKClient")
      ) and
      algo = "pyjwk-client"
    )

    or

    // PyJWKClient instance methods
    (
      api = "PyJWT" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%[Cc]lient%") and
        (
          (attr.getName() = "get_signing_key_from_jwt" and algo = "pyjwk-client-key-from-jwt") or
          (attr.getName() = "get_signing_key_from_jku" and algo = "pyjwk-client-key-from-jku") or
          (attr.getName() = "get_jwk_set" and algo = "pyjwk-client-get-jwk-set")
        )
      ) and
      fileImportsJwt(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // PyJWT — PyJWK / PyJWKSet (JSON Web Key management)
    // =============================================================================
    (
      api = "PyJWT" and
      (
        (isConstructorCall(call, "PyJWK") and algo = "pyjwk") or
        (isConstructorCall(call, "PyJWKSet") and algo = "pyjwk-set") or
        (isAttrCall(call, "api_jwk", "PyJWK") and algo = "pyjwk") or
        (isAttrCall(call, "api_jwk", "PyJWKSet") and algo = "pyjwk-set")
      ) and
      fileImportsJwt(call.getLocation().getFile())
    )

    or

    // PyJWK / PyJWKSet class methods (from_dict, from_json)
    (
      api = "PyJWT" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getObject().toString().matches("%PyJWK%") and
           not attr.getObject().toString().matches("%PyJWKSet%") and
           (
             (attr.getName() = "from_dict" and algo = "pyjwk-from-dict") or
             (attr.getName() = "from_json" and algo = "pyjwk-from-json")
           )) or
          (attr.getObject().toString().matches("%PyJWKSet%") and
           (
             (attr.getName() = "from_dict" and algo = "pyjwk-set-from-dict") or
             (attr.getName() = "from_json" and algo = "pyjwk-set-from-json")
           ))
        )
      ) and
      fileImportsJwt(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // python-jose — jose.jwt.encode(), jose.jws.sign(), jose.jwe.encrypt()
    // Also used as: from jose import jwt; jwt.encode(...)
    // =============================================================================

    // jose jwt
    // Guarded: exclude Authlib-style calls (Dict first arg) AND require
    // python-jose-specific constructs (jws/jwe) in the file to distinguish
    // from PyJWT which shares the same jwt.encode()/jwt.decode() API.
    (
      api = "python-jose" and
      isAttrCall(call, "jwt", "encode") and
      not call.getPositionalArg(0) instanceof Dict and
      fileUsesPythonJose(call.getLocation().getFile()) and
      // Distinguish from PyJWT by checking for jose-style keyword 'algorithm'
      (
        exists(string alg | alg = resolveKeywordArg(call, "algorithm") |
          algo = "jose-jwt-sign-" + alg
        )
        or
        (not exists(resolveKeywordArg(call, "algorithm")) and algo = "unresolved")
      )
    )

    or

    // Guarded: exclude Authlib files and require python-jose-specific constructs.
    (
      api = "python-jose" and
      isAttrCall(call, "jwt", "decode") and
      not fileUsesAuthlib(call.getLocation().getFile()) and
      fileUsesPythonJose(call.getLocation().getFile()) and
      algo = "jose-jwt-decode"
    )

    or

    // jose jws
    (
      api = "python-jose" and
      isAttrCall(call, "jws", "sign") and
      (
        exists(string alg | alg = resolveKeywordArg(call, "algorithm") |
          algo = "jose-jws-sign-" + alg
        )
        or
        (not exists(resolveKeywordArg(call, "algorithm")) and algo = "unresolved")
      )
    )

    or

    (isAttrCall(call, "jws", "verify") and algo = "jose-jws-verify" and api = "python-jose")

    or

    // jose jws — get_unverified_header / get_unverified_headers
    (isAttrCall(call, "jws", "get_unverified_header") and algo = "jose-jws-unverified-header" and api = "python-jose")

    or

    (isAttrCall(call, "jws", "get_unverified_headers") and algo = "jose-jws-unverified-headers" and api = "python-jose")

    or

    // jose jwe
    (
      api = "python-jose" and
      isAttrCall(call, "jwe", "encrypt") and
      (
        exists(string alg | alg = resolveKeywordArg(call, "algorithm") |
          algo = "jose-jwe-encrypt-" + alg
        )
        or
        (not exists(resolveKeywordArg(call, "algorithm")) and algo = "unresolved")
      )
    )

    or

    (isAttrCall(call, "jwe", "decrypt") and algo = "jose-jwe-decrypt" and api = "python-jose")

    or

    // jose jwe — get_unverified_header
    (isAttrCall(call, "jwe", "get_unverified_header") and algo = "jose-jwe-unverified-header" and api = "python-jose")

    or

    // jose jwk — key construction
    (isAttrCall(call, "jwk", "construct") and algo = "jose-jwk-construct" and api = "python-jose")

    or

    // =============================================================================
    // PyNaCl (libsodium) — nacl.secret, nacl.public, nacl.signing, nacl.pwhash
    // =============================================================================

    // SecretBox — XSalsa20-Poly1305
    (isConstructorCall(call, "SecretBox") and algo = "xsalsa20-poly1305" and api = "PyNaCl") or
    (isAttrCall(call, "SecretBox", "encrypt") and algo = "xsalsa20-poly1305-encrypt" and api = "PyNaCl") or
    (isAttrCall(call, "SecretBox", "decrypt") and algo = "xsalsa20-poly1305-decrypt" and api = "PyNaCl")

    or

    // Box — X25519+XSalsa20-Poly1305
    (
      isConstructorCall(call, "Box") and
      // Guard: file must have nacl-related imports
      (
        call.getLocation().getFile().toString().matches("%nacl%") or
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "SecretBox" or n.getId() = "SealedBox" or
           n.getId() = "SigningKey" or n.getId() = "VerifyKey" or
           n.getId() = "PrivateKey" or n.getId() = "PublicKey")
        ) or
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          a.getObject().(Name).getId() = "nacl"
        )
      ) and
      algo = "x25519-xsalsa20-poly1305" and api = "PyNaCl"
    )

    or

    // Box/SealedBox instance methods — encrypt/decrypt/shared_key
    (
      api = "PyNaCl" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "encrypt" and algo = "nacl-box-encrypt") or
          (attr.getName() = "decrypt" and algo = "nacl-box-decrypt") or
          (attr.getName() = "shared_key" and algo = "nacl-box-shared-key")
        ) and
        (
          attr.getObject().toString().matches("%[Bb]ox%") or
          attr.getObject().toString().matches("%sealed%")
        )
      ) and
      (
        call.getLocation().getFile().toString().matches("%nacl%") or
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "Box" or n.getId() = "SealedBox" or n.getId() = "SecretBox")
        )
      )
    )

    or

    // nacl.hash module
    (
      api = "PyNaCl" and
      exists(Attribute attr, Name mod |
        call.getFunc() = attr and
        attr.getObject() = mod and
        mod.getId() = "hash" and
        (
          (attr.getName() = "sha256" and algo = "nacl-sha256") or
          (attr.getName() = "sha512" and algo = "nacl-sha512") or
          (attr.getName() = "blake2b" and algo = "nacl-blake2b") or
          (attr.getName() = "siphash24" and algo = "nacl-siphash24") or
          (attr.getName() = "siphashx24" and algo = "nacl-siphashx24")
        )
      ) and
      (
        call.getLocation().getFile().toString().matches("%nacl%") or
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "SecretBox" or n.getId() = "SigningKey" or n.getId() = "nacl")
        )
      )
    )

    or

    // SealedBox
    (isConstructorCall(call, "SealedBox") and algo = "x25519-xsalsa20-poly1305-sealed" and api = "PyNaCl")

    or

    // SigningKey — Ed25519
    // Guard: require nacl evidence to avoid overlap with python-ecdsa SigningKey
    (
      api = "PyNaCl" and
      (
        call.getLocation().getFile().toString().matches("%nacl%") or
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "SecretBox" or n.getId() = "SealedBox" or n.getId() = "nacl")
        )
      ) and
      (
        (isClassMethodCall(call, "SigningKey", "generate") and algo = "ed25519-keygen") or
        (isConstructorCall(call, "SigningKey") and algo = "ed25519-signing-key") or
        (isConstructorCall(call, "VerifyKey") and algo = "ed25519-verify-key")
      )
    )

    or

    // PrivateKey — X25519
    (isClassMethodCall(call, "PrivateKey", "generate") and algo = "x25519-keygen" and api = "PyNaCl")

    or

    // nacl.pwhash — legacy top-level function
    (
      api = "PyNaCl" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "kdf_scryptsalsa208sha256" and algo = "scrypt-salsa208-sha256") or
          (attr.getName() = "argon2id" and algo = "argon2id") or
          (attr.getName() = "argon2i" and algo = "argon2i")
        )
      )
    )

    or

    // nacl.pwhash.str() / nacl.pwhash.verify() — top-level password hashing
    (
      api = "PyNaCl" and
      (
        (isAttrCall(call, "pwhash", "str") and algo = "nacl-pwhash-str") or
        (isAttrCall(call, "pwhash", "verify") and algo = "nacl-pwhash-verify")
      )
    )

    or

    // nacl.pwhash per-mechanism — argon2id.kdf/str/verify, argon2i.kdf/str/verify, scrypt.kdf/str/verify
    (
      api = "PyNaCl" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getObject().(Name).getId() = "argon2id" and
            (
              (attr.getName() = "kdf" and algo = "nacl-argon2id-kdf") or
              (attr.getName() = "str" and algo = "nacl-argon2id-str") or
              (attr.getName() = "verify" and algo = "nacl-argon2id-verify")
            )
          ) or
          (attr.getObject().(Name).getId() = "argon2i" and
            (
              (attr.getName() = "kdf" and algo = "nacl-argon2i-kdf") or
              (attr.getName() = "str" and algo = "nacl-argon2i-str") or
              (attr.getName() = "verify" and algo = "nacl-argon2i-verify")
            )
          ) or
          (attr.getObject().(Name).getId() = "scrypt" and
            (
              (attr.getName() = "kdf" and algo = "nacl-scrypt-kdf") or
              (attr.getName() = "str" and algo = "nacl-scrypt-str") or
              (attr.getName() = "verify" and algo = "nacl-scrypt-verify")
            )
          )
        )
      ) and
      (
        call.getLocation().getFile().toString().matches("%nacl%") or
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "SecretBox" or n.getId() = "SigningKey" or
           n.getId() = "pwhash" or n.getId() = "nacl")
        )
      )
    )

    or

    // nacl.utils.random() / nacl.utils.randombytes_deterministic()
    (
      api = "PyNaCl" and
      (
        (isAttrCall(call, "utils", "random") and algo = "csprng-nacl-random") or
        (isAttrCall(call, "utils", "randombytes_deterministic") and algo = "nacl-randombytes-deterministic")
      )
    )

    or

    // =============================================================================
    // paramiko — SSH
    // =============================================================================
    (isAttrCall(call, "paramiko", "SSHClient") and algo = "ssh-client" and api = "paramiko") or
    (isConstructorCall(call, "SSHClient") and algo = "ssh-client" and api = "paramiko") or
    (isAttrCall(call, "paramiko", "Transport") and algo = "ssh-transport" and api = "paramiko") or
    (isConstructorCall(call, "Transport") and algo = "ssh-transport" and api = "paramiko")

    or

    // paramiko key types
    (isAttrCall(call, "RSAKey", "generate") and algo = "ssh-rsa-keygen" and api = "paramiko") or
    (isAttrCall(call, "ECDSAKey", "generate") and algo = "ssh-ecdsa-keygen" and api = "paramiko") or
    (isAttrCall(call, "Ed25519Key", "generate") and algo = "ssh-ed25519-keygen" and api = "paramiko") or
    (isAttrCall(call, "DSSKey", "generate") and algo = "ssh-dss-keygen" and api = "paramiko")

    or

    // paramiko key loading (class methods)
    (
      api = "paramiko" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "from_private_key_file" and algo = "ssh-key-load") or
          (attr.getName() = "from_private_key" and algo = "ssh-key-load")
        ) and
        // Guard: receiver should be a key class
        (
          attr.getObject().(Name).getId() = ["RSAKey", "ECDSAKey", "Ed25519Key", "DSSKey"] or
          attr.getObject().toString().matches("%Key%")
        )
      )
    )

    or

    // =============================================================================
    // pyOpenSSL — OpenSSL.crypto
    // =============================================================================
    (
      api = "pyOpenSSL" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%crypto%") and
        (
          (attr.getName() = "PKey"             and algo = "openssl-pkey") or
          (attr.getName() = "X509"             and algo = "openssl-x509") or
          (attr.getName() = "X509Req"          and algo = "openssl-x509-req") or
          (attr.getName() = "load_certificate" and algo = "openssl-load-cert") or
          (attr.getName() = "load_privatekey"  and algo = "openssl-load-privkey") or
          (attr.getName() = "dump_certificate" and algo = "openssl-dump-cert") or
          (attr.getName() = "dump_privatekey"  and algo = "openssl-dump-privkey") or
          (attr.getName() = "sign"             and algo = "openssl-sign") or
          (attr.getName() = "verify"           and algo = "openssl-verify")
        )
      )
    )

    or

    // pyOpenSSL context
    (
      api = "pyOpenSSL" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%SSL%") and
        attr.getName() = "Context" and
        algo = "openssl-ssl-context"
      )
    )

    or

    // pyOpenSSL SSL Context instance methods — set_cipher_list, set_options, set_verify
    (
      api = "pyOpenSSL" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "set_cipher_list" and algo = "openssl-set-cipher-list") or
          (attr.getName() = "set_options"     and algo = "openssl-set-options") or
          (attr.getName() = "set_verify"      and algo = "openssl-set-verify")
        ) and
        (
          attr.getObject().toString().matches("%[Cc]ontext%") or
          attr.getObject().toString().matches("%ctx%") or
          attr.getObject().toString().matches("%ssl%context%")
        )
      ) and
      (
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          (a.getObject().(Name).getId() = "crypto" or a.getObject().(Name).getId() = "SSL" or
           a.getObject().(Name).getId() = "OpenSSL")
        ) or
        call.getLocation().getFile().toString().matches("%openssl%") or
        call.getLocation().getFile().toString().matches("%OpenSSL%")
      )
    )

    or

    // pyOpenSSL PKCS12 / PKCS7 / CRL
    (
      api = "pyOpenSSL" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%crypto%") and
        (
          (attr.getName() = "load_pkcs12"  and algo = "openssl-load-pkcs12") or
          (attr.getName() = "PKCS12"       and algo = "openssl-pkcs12") or
          (attr.getName() = "load_pkcs7_data" and algo = "openssl-load-pkcs7") or
          (attr.getName() = "PKCS7"        and algo = "openssl-pkcs7") or
          (attr.getName() = "CRL"          and algo = "openssl-crl") or
          (attr.getName() = "load_crl"     and algo = "openssl-load-crl") or
          (attr.getName() = "X509Store"    and algo = "openssl-x509-store") or
          (attr.getName() = "X509StoreContext" and algo = "openssl-x509-store-context") or
          (attr.getName() = "dump_publickey"   and algo = "openssl-dump-pubkey") or
          (attr.getName() = "load_publickey"   and algo = "openssl-load-pubkey") or
          (attr.getName() = "dump_certificate_request" and algo = "openssl-dump-csr") or
          (attr.getName() = "get_elliptic_curves" and algo = "openssl-get-ec-curves") or
          (attr.getName() = "get_elliptic_curve"  and algo = "openssl-get-ec-curve") or
          (attr.getName() = "NetscapeSPKI" and algo = "openssl-netscape-spki") or
          (attr.getName() = "Revoked"      and algo = "openssl-revoked")
        )
      )
    )

    or

    // pyOpenSSL SSL.Connection — guarded to exclude Fabric's Connection
    (
      api = "pyOpenSSL" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%SSL%") and
        attr.getName() = "Connection" and
        algo = "openssl-ssl-connection"
      )
    )

    or

    // pyOpenSSL SSL.Connection constructor (bare name) — requires pyOpenSSL import evidence
    (
      api = "pyOpenSSL" and
      isConstructorCall(call, "Connection") and
      not call.getLocation().getFile().toString().matches("%fabric%") and
      (
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          (a.getObject().(Name).getId() = "SSL" or a.getObject().(Name).getId() = "OpenSSL")
        )
      ) and
      algo = "openssl-ssl-connection"
    )

    or

    // pyOpenSSL SSL Context additional methods — use_certificate, use_privatekey, etc.
    // load_verify_locations guarded: only fires when file has pyOpenSSL import evidence
    // (to avoid overlap with StdlibCrypto.ql's ssl module detection)
    (
      api = "pyOpenSSL" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "use_certificate"      and algo = "openssl-ctx-use-cert") or
          (attr.getName() = "use_certificate_file" and algo = "openssl-ctx-use-cert-file") or
          (attr.getName() = "use_privatekey"       and algo = "openssl-ctx-use-privkey") or
          (attr.getName() = "use_privatekey_file"  and algo = "openssl-ctx-use-privkey-file") or
          (attr.getName() = "use_certificate_chain_file" and algo = "openssl-ctx-use-chain-file") or
          (attr.getName() = "load_verify_locations" and algo = "openssl-ctx-load-verify-locations") or
          (attr.getName() = "set_min_proto_version" and algo = "openssl-ctx-min-proto") or
          (attr.getName() = "set_max_proto_version" and algo = "openssl-ctx-max-proto") or
          (attr.getName() = "set_alpn_protos"      and algo = "openssl-ctx-set-alpn")
        ) and
        (
          attr.getObject().toString().matches("%[Cc]ontext%") or
          attr.getObject().toString().matches("%ctx%")
        )
      ) and
      // Guard: require pyOpenSSL import evidence to prevent overlap with stdlib ssl
      (
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          (a.getObject().(Name).getId() = "SSL" or a.getObject().(Name).getId() = "OpenSSL")
        ) or
        exists(ImportExpr ie |
          ie.getLocation().getFile() = call.getLocation().getFile() and
          ie.toString().matches("%OpenSSL%")
        )
      )
    )

    or

    // =============================================================================
    // pyOpenSSL — OpenSSL.rand (random number generation)
    // =============================================================================
    (
      api = "pyOpenSSL" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%rand%") and
        (
          (attr.getName() = "bytes"  and algo = "openssl-rand-bytes") or
          (attr.getName() = "add"    and algo = "openssl-rand-add") or
          (attr.getName() = "status" and algo = "openssl-rand-status")
        )
      ) and
      (
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          (a.getObject().(Name).getId() = "OpenSSL" or a.getObject().(Name).getId() = "rand")
        ) or
        call.getLocation().getFile().toString().matches("%openssl%") or
        call.getLocation().getFile().toString().matches("%OpenSSL%")
      )
    )

    or

    // =============================================================================
    // python-gnupg — gnupg.GPG
    // =============================================================================
    (
      api = "gnupg" and
      (
        (isAttrCall(call, "gnupg", "GPG") and algo = "gpg-init") or
        (isConstructorCall(call, "GPG") and algo = "gpg-init")
      )
    )

    or

    // GPG method calls
    (
      api = "gnupg" and
      fileImportsGnupg(call.getLocation().getFile()) and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "encrypt"       and algo = "gpg-encrypt") or
          (attr.getName() = "decrypt"       and algo = "gpg-decrypt") or
          (attr.getName() = "sign"          and algo = "gpg-sign") or
          (attr.getName() = "verify"        and algo = "gpg-verify") or
          (attr.getName() = "gen_key"       and algo = "gpg-keygen") or
          (attr.getName() = "gen_key_input" and algo = "gpg-keygen-input") or
          (attr.getName() = "import_keys"   and algo = "gpg-import-keys") or
          (attr.getName() = "export_keys"   and algo = "gpg-export-keys") or
          (attr.getName() = "encrypt_file"  and algo = "gpg-encrypt-file") or
          (attr.getName() = "decrypt_file"  and algo = "gpg-decrypt-file") or
          (attr.getName() = "sign_file"     and algo = "gpg-sign-file") or
          (attr.getName() = "verify_file"   and algo = "gpg-verify-file") or
          (attr.getName() = "recv_keys"     and algo = "gpg-recv-keys") or
          (attr.getName() = "send_keys"     and algo = "gpg-send-keys") or
          (attr.getName() = "search_keys"   and algo = "gpg-search-keys") or
          (attr.getName() = "delete_keys"   and algo = "gpg-delete-keys") or
          (attr.getName() = "list_keys"     and algo = "gpg-list-keys") or
          (attr.getName() = "scan_keys"     and algo = "gpg-scan-keys") or
          (attr.getName() = "trust_keys"    and algo = "gpg-trust-keys")
        )
      )
    )

    or

    // =============================================================================
    // ecdsa — python-ecdsa library
    // =============================================================================
    (
      api = "ecdsa" and
      isAttrCall(call, "SigningKey", "generate") and
      // Guard: exclude PyNaCl files to avoid overlap with PyNaCl SigningKey.generate
      not (
        call.getLocation().getFile().toString().matches("%nacl%") or
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "SecretBox" or n.getId() = "SealedBox" or n.getId() = "nacl")
        )
      ) and
      (
        // With curve parameter: SigningKey.generate(curve=SECP256k1)
        exists(Keyword kw, Name curveRef |
          call.getAKeyword() = kw and
          kw.getArg() = "curve" and
          kw.getValue() = curveRef and
          algo = "ecdsa-keygen-" + curveRef.getId().toLowerCase()
        )
        or
        // Positional curve argument
        exists(Name curveRef |
          call.getPositionalArg(0) = curveRef and
          algo = "ecdsa-keygen-" + curveRef.getId().toLowerCase()
        )
        or
        (
          not exists(Keyword kw | call.getAKeyword() = kw and kw.getArg() = "curve") and
          not call.getPositionalArg(0) instanceof Name and
          algo = "unresolved"
        )
      )
    )

    or

    (
      api = "ecdsa" and
      isAttrCall(call, "SigningKey", "from_string") and algo = "ecdsa-import"
    )

    or

    (
      api = "ecdsa" and
      isAttrCall(call, "SigningKey", "from_pem") and algo = "ecdsa-import-pem"
    )

    or

    (
      api = "ecdsa" and
      isAttrCall(call, "SigningKey", "from_der") and algo = "ecdsa-import-der"
    )

    or

    // python-ecdsa sign/verify instance methods
    (
      api = "ecdsa" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "sign" and algo = "ecdsa-sign") or
          (attr.getName() = "sign_deterministic" and algo = "ecdsa-sign-deterministic") or
          (attr.getName() = "verify" and algo = "ecdsa-verify")
        ) and
        (
          attr.getObject().toString().matches("%[Ss]igning%[Kk]ey%") or
          attr.getObject().toString().matches("%[Vv]erifying%[Kk]ey%") or
          attr.getObject().toString().matches("%sk%") or
          attr.getObject().toString().matches("%vk%")
        )
      ) and
      // Guard: file must have ecdsa-related imports
      exists(Name n |
        n.getLocation().getFile() = call.getLocation().getFile() and
        (n.getId() = "SigningKey" or n.getId() = "VerifyingKey" or n.getId() = "ECDSA")
      )
    )

    or

    // VerifyingKey import methods
    (
      api = "ecdsa" and
      (
        (isAttrCall(call, "VerifyingKey", "from_string") and algo = "ecdsa-vk-import") or
        (isAttrCall(call, "VerifyingKey", "from_pem") and algo = "ecdsa-vk-import-pem") or
        (isAttrCall(call, "VerifyingKey", "from_der") and algo = "ecdsa-vk-import-der") or
        (isAttrCall(call, "VerifyingKey", "from_public_key_recovery") and algo = "ecdsa-vk-recover") or
        (isAttrCall(call, "VerifyingKey", "from_public_key_recovery_with_digest") and algo = "ecdsa-vk-recover-digest")
      )
    )

    or

    // =============================================================================
    // rsa — python-rsa library
    // =============================================================================
    (isAttrCall(call, "rsa", "newkeys") and algo = "rsa-keygen" and api = "python-rsa") or
    (isAttrCall(call, "rsa", "encrypt") and algo = "rsa-encrypt" and api = "python-rsa") or
    (isAttrCall(call, "rsa", "decrypt") and algo = "rsa-decrypt" and api = "python-rsa") or
    (isAttrCall(call, "rsa", "sign")    and algo = "rsa-sign" and api = "python-rsa") or
    (isAttrCall(call, "rsa", "verify")  and algo = "rsa-verify" and api = "python-rsa")

    or

    // =============================================================================
    // itsdangerous — URL-safe signing (used by Flask)
    // =============================================================================
    (
      api = "itsdangerous" and
      (
        (isConstructorCall(call, "URLSafeTimedSerializer") and algo = "url-safe-timed-serializer") or
        (isConstructorCall(call, "URLSafeSerializer")      and algo = "url-safe-serializer") or
        (isConstructorCall(call, "Signer")                 and algo = "signer") or
        (isConstructorCall(call, "TimestampSigner")        and algo = "timestamp-signer") or
        (isConstructorCall(call, "Serializer")             and algo = "serializer")
      ) and
      // Guard: disambiguate from Django Signer
      fileImportsItsdangerous(call.getLocation().getFile())
    )

    or

    // itsdangerous instance methods: .dumps(), .loads(), .sign(), .unsign()
    (
      api = "itsdangerous" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "dumps"  and algo = "itsdangerous-dumps") or
          (attr.getName() = "loads"  and algo = "itsdangerous-loads") or
          (attr.getName() = "sign"   and algo = "itsdangerous-sign") or
          (attr.getName() = "unsign" and algo = "itsdangerous-unsign") or
          (attr.getName() = "dump_payload"  and algo = "itsdangerous-dump-payload") or
          (attr.getName() = "load_payload"  and algo = "itsdangerous-load-payload") or
          (attr.getName() = "loads_unsafe"  and algo = "itsdangerous-loads-unsafe") or
          (attr.getName() = "load_unsafe"   and algo = "itsdangerous-load-unsafe") or
          (attr.getName() = "derive_key"    and algo = "itsdangerous-derive-key") or
          (attr.getName() = "get_signature" and algo = "itsdangerous-get-signature")
        )
      ) and
      fileImportsItsdangerous(call.getLocation().getFile())
    )

    or

    // itsdangerous — NoneAlgorithm (no-op signing, insecure)
    (
      api = "itsdangerous" and
      isConstructorCall(call, "NoneAlgorithm") and
      fileImportsItsdangerous(call.getLocation().getFile()) and
      algo = "itsdangerous-none-algorithm"
    )

    or

    // =============================================================================
    // Fido2 / WebAuthn
    // =============================================================================
    (
      api = "fido2" and
      (
        (isConstructorCall(call, "Fido2Server") and algo = "fido2-server") or
        (isConstructorCall(call, "Fido2Client") and algo = "fido2-client") or
        (isConstructorCall(call, "RelyingParty") and algo = "fido2-relying-party")
      )
    )

    or

    // Fido2 registration/authentication methods
    (
      api = "fido2" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "register_begin"        and algo = "fido2-register-begin") or
          (attr.getName() = "register_complete"     and algo = "fido2-register-complete") or
          (attr.getName() = "authenticate_begin"    and algo = "fido2-auth-begin") or
          (attr.getName() = "authenticate_complete" and algo = "fido2-auth-complete") or
          (attr.getName() = "begin_registration"    and algo = "fido2-register-begin") or
          (attr.getName() = "begin_authentication"  and algo = "fido2-auth-begin") or
          (attr.getName() = "complete_registration" and algo = "fido2-register-complete") or
          (attr.getName() = "complete_authentication" and algo = "fido2-auth-complete")
        ) and
        (
          attr.getObject().toString().matches("%[Ss]erver%") or
          attr.getObject().toString().matches("%fido%")
        )
      )
    )

    or

    // =============================================================================
    // Web3 / Ethereum (web3.py, eth-account, eth-keys)
    // =============================================================================
    (
      api = "web3" and
      (
        (isAttrCall(call, "Account", "create")             and algo = "eth-account-create") or
        (isAttrCall(call, "Account", "sign_message")       and algo = "eth-sign-message") or
        (isAttrCall(call, "Account", "sign_transaction")   and algo = "eth-sign-transaction") or
        (isAttrCall(call, "Account", "from_key")           and algo = "eth-account-import") or
        (isAttrCall(call, "Account", "recover_message")    and algo = "eth-recover-message")
      )
    )

    or

    (
      api = "eth-keys" and
      isAttrCall(call, "KeyAPI", "PrivateKey") and algo = "eth-private-key"
    )

    or

    // =============================================================================
    // PyNaCl — Additional operations
    // =============================================================================

    // nacl.secret.Aead (XChaCha20-Poly1305 AEAD)
    (isConstructorCall(call, "Aead") and algo = "xchacha20-poly1305-aead" and api = "PyNaCl")

    or

    // nacl.bindings — low-level bindings
    (
      api = "PyNaCl" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%bindings%") and
        (
          (attr.getName() = "crypto_secretbox"        and algo = "nacl-secretbox") or
          (attr.getName() = "crypto_secretbox_open"   and algo = "nacl-secretbox-open") or
          (attr.getName() = "crypto_box"              and algo = "nacl-box") or
          (attr.getName() = "crypto_box_open"         and algo = "nacl-box-open") or
          (attr.getName() = "crypto_sign"             and algo = "nacl-sign") or
          (attr.getName() = "crypto_sign_open"        and algo = "nacl-sign-open") or
          (attr.getName() = "crypto_aead_chacha20poly1305_ietf_encrypt" and algo = "nacl-aead-encrypt") or
          (attr.getName() = "crypto_aead_chacha20poly1305_ietf_decrypt" and algo = "nacl-aead-decrypt") or
          (attr.getName() = "crypto_aead_xchacha20poly1305_ietf_encrypt" and algo = "nacl-xchacha-encrypt") or
          (attr.getName() = "crypto_aead_xchacha20poly1305_ietf_decrypt" and algo = "nacl-xchacha-decrypt") or
          (attr.getName() = "crypto_scalarmult"       and algo = "nacl-scalarmult") or
          (attr.getName() = "crypto_generichash"      and algo = "nacl-generichash") or
          (attr.getName() = "crypto_shorthash"        and algo = "nacl-shorthash") or
          (attr.getName() = "randombytes"             and algo = "nacl-randombytes") or
          (attr.getName() = "crypto_kdf_derive_from_key" and algo = "nacl-kdf-derive")
        )
      )
    )

    or

    // PyNaCl signing operations — sign/verify
    (
      api = "PyNaCl" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "sign" and algo = "ed25519-sign") or
          (attr.getName() = "verify" and algo = "ed25519-verify")
        ) and
        (
          attr.getObject().toString().matches("%[Ss]igning%[Kk]ey%") or
          attr.getObject().toString().matches("%[Vv]erify%[Kk]ey%") or
          attr.getObject().toString().matches("%sk%") or
          attr.getObject().toString().matches("%vk%")
        )
      ) and
      (
        call.getLocation().getFile().toString().matches("%nacl%") or
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "SigningKey" or n.getId() = "VerifyKey")
        )
      )
    )

    or

    // PyNaCl key exchange — PrivateKey/PublicKey operations
    (
      api = "PyNaCl" and
      isConstructorCall(call, "PrivateKey") and
      (
        call.getLocation().getFile().toString().matches("%nacl%") or
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "PublicKey" or n.getId() = "SecretBox" or n.getId() = "Box")
        )
      ) and
      algo = "x25519-private-key"
    )

    or

    (
      api = "PyNaCl" and
      isConstructorCall(call, "PublicKey") and
      (
        call.getLocation().getFile().toString().matches("%nacl%") or
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "PrivateKey" or n.getId() = "SecretBox" or n.getId() = "Box")
        )
      ) and
      algo = "x25519-public-key"
    )

    or

    // =============================================================================
    // paramiko — Additional SSH operations
    // =============================================================================

    // paramiko SFTPClient (SSH file transfer)
    (
      api = "paramiko" and
      (
        (isAttrCall(call, "paramiko", "SFTPClient") and algo = "ssh-sftp-client") or
        (isConstructorCall(call, "SFTPClient") and algo = "ssh-sftp-client") or
        (
          exists(Attribute attr |
            call.getFunc() = attr and
            attr.getName() = "open_sftp" and
            algo = "ssh-sftp-open"
          )
        )
      )
    )

    or

    // paramiko Agent
    (
      api = "paramiko" and
      (
        (isAttrCall(call, "paramiko", "Agent") and algo = "ssh-agent") or
        (isConstructorCall(call, "Agent") and algo = "ssh-agent")
      )
    )

    or

    // paramiko connection/auth methods
    (
      api = "paramiko" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "connect"         and algo = "ssh-connect") or
          (attr.getName() = "exec_command"    and algo = "ssh-exec") or
          (attr.getName() = "invoke_shell"    and algo = "ssh-shell") or
          (attr.getName() = "get_transport"   and algo = "ssh-get-transport") or
          (attr.getName() = "get_security_options" and algo = "ssh-security-options") or
          (attr.getName() = "load_system_host_keys" and algo = "ssh-host-keys") or
          (attr.getName() = "set_missing_host_key_policy" and algo = "ssh-host-key-policy")
        ) and
        (
          attr.getObject().toString().matches("%[Ss][Ss][Hh]%") or
          attr.getObject().toString().matches("%client%") or
          attr.getObject().toString().matches("%ssh%") or
          attr.getObject().toString().matches("%[Tt]ransport%")
        )
      )
    )

    or

    // paramiko host key policies
    (
      api = "paramiko" and
      (
        (isConstructorCall(call, "AutoAddPolicy") and algo = "ssh-auto-add-policy") or
        (isConstructorCall(call, "RejectPolicy")  and algo = "ssh-reject-policy") or
        (isConstructorCall(call, "WarningPolicy") and algo = "ssh-warning-policy")
      )
    )

    or

    // paramiko key class constructors (importing keys from data)
    (
      api = "paramiko" and
      (
        (isConstructorCall(call, "RSAKey")     and algo = "ssh-rsa-key-import") or
        (isConstructorCall(call, "ECDSAKey")   and algo = "ssh-ecdsa-key-import") or
        (isConstructorCall(call, "Ed25519Key") and algo = "ssh-ed25519-key-import") or
        (isConstructorCall(call, "DSSKey")     and algo = "ssh-dss-key-import") or
        (isAttrCall(call, "paramiko", "RSAKey")     and algo = "ssh-rsa-key-import") or
        (isAttrCall(call, "paramiko", "ECDSAKey")   and algo = "ssh-ecdsa-key-import") or
        (isAttrCall(call, "paramiko", "Ed25519Key") and algo = "ssh-ed25519-key-import") or
        (isAttrCall(call, "paramiko", "DSSKey")     and algo = "ssh-dss-key-import")
      )
    )

    or

    // paramiko key export — write_private_key_file / write_private_key
    (
      api = "paramiko" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "write_private_key_file" and algo = "ssh-key-export-file") or
          (attr.getName() = "write_private_key"      and algo = "ssh-key-export")
        ) and
        (
          attr.getObject().toString().matches("%[Kk]ey%") or
          attr.getObject().toString().matches("%rsa%") or
          attr.getObject().toString().matches("%ecdsa%") or
          attr.getObject().toString().matches("%ed25519%") or
          attr.getObject().toString().matches("%dss%")
        )
      )
    )

    or

    // paramiko low-level signing/verification
    (
      api = "paramiko" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "sign_ssh_data"  and algo = "ssh-sign-data") or
          (attr.getName() = "verify_ssh_sig" and algo = "ssh-verify-sig")
        ) and
        (
          attr.getObject().toString().matches("%[Kk]ey%") or
          attr.getObject().toString().matches("%rsa%") or
          attr.getObject().toString().matches("%ecdsa%") or
          attr.getObject().toString().matches("%ed25519%") or
          attr.getObject().toString().matches("%dss%")
        )
      )
    )

    or

    // paramiko key fingerprint / serialization
    (
      api = "paramiko" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "get_fingerprint" and algo = "ssh-key-fingerprint") or
          (attr.getName() = "get_base64"      and algo = "ssh-key-base64") or
          (attr.getName() = "asbytes"         and algo = "ssh-key-bytes")
        ) and
        (
          attr.getObject().toString().matches("%[Kk]ey%") or
          attr.getObject().toString().matches("%rsa%") or
          attr.getObject().toString().matches("%ecdsa%") or
          attr.getObject().toString().matches("%ed25519%") or
          attr.getObject().toString().matches("%dss%")
        )
      )
    )

    or

    // paramiko Transport.get_remote_server_key()
    (
      api = "paramiko" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "get_remote_server_key" and
        (
          attr.getObject().toString().matches("%[Tt]ransport%") or
          attr.getObject().toString().matches("%transport%")
        )
      ) and
      algo = "ssh-remote-server-key"
    )

    or

    // paramiko HostKeys management
    (
      api = "paramiko" and
      (
        (isAttrCall(call, "paramiko", "HostKeys") and algo = "ssh-hostkeys") or
        (isConstructorCall(call, "HostKeys") and algo = "ssh-hostkeys")
      )
    )

    or

    // paramiko HostKeys instance methods
    (
      api = "paramiko" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "add"  and algo = "ssh-hostkeys-add") or
          (attr.getName() = "load" and algo = "ssh-hostkeys-load") or
          (attr.getName() = "save" and algo = "ssh-hostkeys-save")
        ) and
        (
          attr.getObject().toString().matches("%[Hh]ost%[Kk]ey%") or
          attr.getObject().toString().matches("%known_hosts%")
        )
      )
    )

    or

    // =============================================================================
    // pyOpenSSL — Additional operations
    // =============================================================================

    // X509Extension
    (
      api = "pyOpenSSL" and
      (
        isConstructorCall(call, "X509Extension") and algo = "openssl-x509-extension"
      )
    )

    or

    // pyOpenSSL key type generation: PKey.generate_key(type, bits)
    (
      api = "pyOpenSSL" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "generate_key" and
        (
          attr.getObject().toString().matches("%[Pp][Kk]ey%") or
          attr.getObject().toString().matches("%key%")
        )
      ) and
      (
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          a.getObject().(Name).getId() = "crypto"
        ) or
        call.getLocation().getFile().toString().matches("%openssl%") or
        call.getLocation().getFile().toString().matches("%OpenSSL%")
      ) and
      algo = "openssl-keygen"
    )

    or

    // pyOpenSSL certificate operations
    (
      api = "pyOpenSSL" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "sign"           and algo = "openssl-cert-sign") or
          (attr.getName() = "set_pubkey"     and algo = "openssl-set-pubkey") or
          (attr.getName() = "get_pubkey"     and algo = "openssl-get-pubkey") or
          (attr.getName() = "set_serial_number" and algo = "openssl-set-serial") or
          (attr.getName() = "get_serial_number" and algo = "openssl-get-serial") or
          (attr.getName() = "get_signature_algorithm" and algo = "openssl-get-sig-algo")
        ) and
        (
          attr.getObject().toString().matches("%[Cc]ert%") or
          attr.getObject().toString().matches("%x509%") or
          attr.getObject().toString().matches("%X509%")
        )
      ) and
      (
        exists(Attribute a |
          a.getLocation().getFile() = call.getLocation().getFile() and
          (a.getObject().(Name).getId() = "crypto" or a.getObject().(Name).getId() = "OpenSSL")
        )
      )
    )

    or

    // =============================================================================
    // Fabric — SSH-based remote execution (uses paramiko internally)
    // =============================================================================
    (
      api = "fabric" and
      (
        (isConstructorCall(call, "Connection") and algo = "fabric-connection") or
        (
          exists(Attribute attr |
            call.getFunc() = attr and
            attr.getObject().toString().matches("%fabric%") and
            attr.getName() = "Connection" and
            algo = "fabric-connection"
          )
        )
      )
    )

    or

    // Fabric run/sudo (remote execution over SSH)
    (
      api = "fabric" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "run"  and algo = "fabric-run") or
          (attr.getName() = "sudo" and algo = "fabric-sudo") or
          (attr.getName() = "put"  and algo = "fabric-put") or
          (attr.getName() = "get"  and algo = "fabric-get")
        ) and
        (
          attr.getObject().toString().matches("%[Cc]onnection%") or
          attr.getObject().toString().matches("%conn%") or
          attr.getObject().toString().matches("%c%")
        )
      ) and
      (
        exists(Name n |
          n.getLocation().getFile() = call.getLocation().getFile() and
          (n.getId() = "Connection" or n.getId() = "fabric")
        )
      )
    )

    or

    // =============================================================================
    // asyncssh — Async SSH library
    // =============================================================================
    (
      api = "asyncssh" and
      (
        (isAttrCall(call, "asyncssh", "connect")       and algo = "asyncssh-connect") or
        (isAttrCall(call, "asyncssh", "create_server") and algo = "asyncssh-server") or
        (isAttrCall(call, "asyncssh", "generate_private_key") and algo = "asyncssh-keygen") or
        (isAttrCall(call, "asyncssh", "read_private_key")     and algo = "asyncssh-read-key") or
        (isAttrCall(call, "asyncssh", "read_certificate")     and algo = "asyncssh-read-cert") or
        (isAttrCall(call, "asyncssh", "import_private_key")   and algo = "asyncssh-import-key")
      )
    )
  )
select call, "algo=" + algo + ", api=" + api
