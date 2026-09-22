/**
 * @name Crypto inventory (Java)
 * @description Quick inventory of common crypto usage (simple heuristics).
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/java-crypto-inventory
 * @tags security
 */

import java

from MethodCall call, StringLiteral lit, string algo
where
  // We mostly care about getInstance("xyz") style usage.
  call.getArgument(0) = lit
  and
  (
    // ===== Digests =====
    (
      call.getMethod().hasName("getInstance") and
      call.getMethod().getDeclaringType().hasName("MessageDigest") and
      (
        (lit.getValue().toLowerCase().matches("%md5%") and algo = "md5") or
        ((lit.getValue().toLowerCase().matches("%sha-1%") or lit.getValue().toLowerCase().matches("%sha1%")) and algo = "sha-1") or
        ((lit.getValue().toLowerCase().matches("%sha-224%") or lit.getValue().toLowerCase().matches("%sha224%")) and algo = "sha-224") or
        ((lit.getValue().toLowerCase().matches("%sha-256%") or lit.getValue().toLowerCase().matches("%sha256%")) and algo = "sha-256") or
        ((lit.getValue().toLowerCase().matches("%sha-384%") or lit.getValue().toLowerCase().matches("%sha384%")) and algo = "sha-384") or
        ((lit.getValue().toLowerCase().matches("%sha-512%") or lit.getValue().toLowerCase().matches("%sha512%")) and algo = "sha-512") or
        (lit.getValue().toLowerCase().matches("%sha3-256%") and algo = "sha3-256") or
        (lit.getValue().toLowerCase().matches("%sha3-512%") and algo = "sha3-512")
      )
    )

    or

    // ===== MACs / HMAC =====
    (
      call.getMethod().hasName("getInstance") and
      call.getMethod().getDeclaringType().hasName("Mac") and
      (
        (lit.getValue().toLowerCase().matches("%hmacsha256%") and algo = "hmac-sha256") or
        (lit.getValue().toLowerCase().matches("%hmacsha384%") and algo = "hmac-sha384") or
        (lit.getValue().toLowerCase().matches("%hmacsha512%") and algo = "hmac-sha512") or
        (lit.getValue().toLowerCase().matches("%hmacsha1%")   and algo = "hmac-sha1") or
        (lit.getValue().toLowerCase().matches("%hmacmd5%")    and algo = "hmac-md5") or
        (lit.getValue().toLowerCase().matches("%hmac%")       and algo = "hmac")
      )
    )

    or

    // ===== Ciphers (JCE) =====
    (
      call.getMethod().hasName("getInstance") and
      call.getMethod().getDeclaringType().hasName("Cipher") and
      (
        (lit.getValue().toLowerCase().matches("%aes/gcm%") and algo = "aes-gcm") or
        (lit.getValue().toLowerCase().matches("%aes/cbc%") and algo = "aes-cbc") or
        (lit.getValue().toLowerCase().matches("%aes/ctr%") and algo = "aes-ctr") or
        (lit.getValue().toLowerCase().matches("%aes/ecb%") and algo = "aes-ecb") or
        (lit.getValue().toLowerCase().matches("%aes%") and algo = "aes") or

        (lit.getValue().toLowerCase().matches("%oaepwithsha-256%") and algo = "rsa-oaep-sha256") or
        (lit.getValue().toLowerCase().matches("%oaepwithsha256%")  and algo = "rsa-oaep-sha256") or
        (lit.getValue().toLowerCase().matches("%oaep%")            and algo = "rsa-oaep") or
        (lit.getValue().toLowerCase().matches("%pkcs1padding%")    and algo = "rsa-pkcs1") or
        (lit.getValue().toLowerCase().matches("%rsa%")             and algo = "rsa") or

        (lit.getValue().toLowerCase().matches("%chacha20%poly1305%") and algo = "chacha20-poly1305")
      )
    )

    or

    // ===== Signatures =====
    (
      call.getMethod().hasName("getInstance") and
      call.getMethod().getDeclaringType().hasName("Signature") and
      (
        (lit.getValue().toLowerCase().matches("%sha256withrsa%")   and algo = "sha256withrsa") or
        (lit.getValue().toLowerCase().matches("%sha384withrsa%")   and algo = "sha384withrsa") or
        (lit.getValue().toLowerCase().matches("%sha512withrsa%")   and algo = "sha512withrsa") or

        (lit.getValue().toLowerCase().matches("%sha256withecdsa%") and algo = "sha256withecdsa") or
        (lit.getValue().toLowerCase().matches("%sha384withecdsa%") and algo = "sha384withecdsa") or
        (lit.getValue().toLowerCase().matches("%sha512withecdsa%") and algo = "sha512withecdsa") or

        (lit.getValue().toLowerCase().matches("%ed25519%")         and algo = "ed25519") or
        (lit.getValue().toLowerCase().matches("%ed448%")           and algo = "ed448") or

        (lit.getValue().toLowerCase().matches("%ecdsa%")           and algo = "ecdsa") or
        (lit.getValue().toLowerCase().matches("%rsa%")             and algo = "rsa-signature")
      )
    )

    or

    // ===== Key generation =====
    (
      call.getMethod().hasName("getInstance") and
      call.getMethod().getDeclaringType().hasName("KeyPairGenerator") and
      (
        (lit.getValue().toLowerCase() = "rsa" and algo = "rsa-keypair") or
        (lit.getValue().toLowerCase() = "ec"  and algo = "ec-keypair") or
        (lit.getValue().toLowerCase().matches("%ed25519%") and algo = "ed25519-keypair") or
        (lit.getValue().toLowerCase().matches("%ed448%")   and algo = "ed448-keypair")
      )
    )

    or

    // ===== Key agreement =====
    (
      call.getMethod().hasName("getInstance") and
      call.getMethod().getDeclaringType().hasName("KeyAgreement") and
      (
        (lit.getValue().toLowerCase().matches("%ecdh%")   and algo = "ecdh") or
        (lit.getValue().toLowerCase().matches("%x25519%") and algo = "x25519") or
        (lit.getValue().toLowerCase().matches("%x448%")   and algo = "x448") or
        (lit.getValue().toLowerCase().matches("%dh%")     and algo = "dh")
      )
    )

    or

    // ===== KDFs =====
    (
      call.getMethod().hasName("getInstance") and
      call.getMethod().getDeclaringType().hasName("SecretKeyFactory") and
      (
        (lit.getValue().toLowerCase().matches("%pbkdf2withhmacsha256%") and algo = "pbkdf2-hmac-sha256") or
        (lit.getValue().toLowerCase().matches("%pbkdf2withhmacsha1%")   and algo = "pbkdf2-hmac-sha1") or
        (lit.getValue().toLowerCase().matches("%pbkdf2%")               and algo = "pbkdf2")
      )
    )

    or

    // ===== Certificates / keystores =====
    (
      call.getMethod().hasName("getInstance") and
      call.getMethod().getDeclaringType().hasName("CertificateFactory") and
      (lit.getValue().toLowerCase().matches("%x.509%") and algo = "x509")
    )

    or

    (
      call.getMethod().hasName("getInstance") and
      call.getMethod().getDeclaringType().hasName("KeyStore") and
      (
        (lit.getValue().toLowerCase().matches("%pkcs12%") and algo = "pkcs12") or
        (lit.getValue().toLowerCase().matches("%jks%")    and algo = "jks") or
        (lit.getValue().toLowerCase().matches("%bks%")    and algo = "bks") or
        (lit.getValue().toLowerCase().matches("%keystore%") and algo = "keystore")
      )
    )

    or

    // ===== TLS =====
    (
      call.getMethod().hasName("getInstance") and
      call.getMethod().getDeclaringType().hasName("SSLContext") and
      (lit.getValue().toLowerCase().matches("%tls%") and algo = "tls")
    )
  )

  or

  //
  // ==== Password4j/password4j-jca
  //     (Argon2 / scrypt / bcrypt exposed through getInstance("..."))
  //
  exists(StringLiteral litr |
    call.getMethod().hasName("getInstance") and
    call.getArgument(0) = litr and

    // "normal" JCA entry points where providers register algorithms
    (
      call.getMethod().getDeclaringType().hasName("SecretKeyFactory") or
      call.getMethod().getDeclaringType().hasName("MessageDigest") or
      call.getMethod().getDeclaringType().hasName("AlgorithmParameters")
    ) and

    (
      // Argon2 variants
      (litr.getValue().toLowerCase().matches("%argon2id%") and algo = "argon2id") or
      (litr.getValue().toLowerCase().matches("%argon2i%")  and algo = "argon2i") or
      (litr.getValue().toLowerCase().matches("%argon2d%")  and algo = "argon2d") or
      (litr.getValue().toLowerCase().matches("%argon2%")   and algo = "argon2") or

      // scrypt
      (litr.getValue().toLowerCase().matches("%scrypt%")   and algo = "scrypt") or

      // bcrypt (sometimes appears as "bcrypt" or "blowfish" in algorithm names)
      (litr.getValue().toLowerCase().matches("%bcrypt%")   and algo = "bcrypt") or
      (litr.getValue().toLowerCase().matches("%blowfish%") and algo = "bcrypt")
    )
  )
 
select call, "algo=" + algo
