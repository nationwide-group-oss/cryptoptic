/**
 * @name Crypto inventory — Password Hashing & KDF Libraries (Python)
 * @description Inventory of password hashing and KDF library usage including
 *              bcrypt, argon2-cffi, passlib, and scrypt.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/python-cbom-password-hashing
 * @tags security
 */

import python
import lib.PyCryptoCommon

from Call call, string algo, string api
where
  (
    // =============================================================================
    // bcrypt — bcrypt.hashpw(), bcrypt.gensalt(), bcrypt.checkpw(), bcrypt.kdf()
    // =============================================================================
    (isAttrCall(call, "bcrypt", "hashpw")  and algo = "bcrypt-hash"  and api = "bcrypt") or
    (isAttrCall(call, "bcrypt", "gensalt") and algo = "bcrypt-salt"  and api = "bcrypt") or
    (isAttrCall(call, "bcrypt", "checkpw") and algo = "bcrypt-check" and api = "bcrypt") or
    (isAttrCall(call, "bcrypt", "kdf")     and algo = "bcrypt-kdf"   and api = "bcrypt")

    or

    // =============================================================================
    // argon2-cffi — argon2.PasswordHasher()
    // =============================================================================

    // Constructor: argon2.PasswordHasher() or PasswordHasher()
    (
      api = "argon2-cffi" and
      (
        (isAttrCall(call, "argon2", "PasswordHasher") and algo = "argon2-hasher") or
        (isConstructorCall(call, "PasswordHasher") and algo = "argon2-hasher")
      )
    )

    or

    // Method calls: ph.hash(password), ph.verify(hash, password), ph.check_needs_rehash(hash)
    (
      api = "argon2-cffi" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "hash" and
           attr.getObject().toString().matches("%[Hh]asher%") and
           algo = "argon2-hash") or
          (attr.getName() = "verify" and
           attr.getObject().toString().matches("%[Hh]asher%") and
           algo = "argon2-verify") or
          (attr.getName() = "check_needs_rehash" and
           attr.getObject().toString().matches("%[Hh]asher%") and
           algo = "argon2-check-needs-rehash")
        )
      )
    )

    or

    // Low-level: argon2.low_level.hash_secret(), argon2.low_level.hash_secret_raw(),
    //            argon2.low_level.verify_secret()
    (
      api = "argon2-cffi" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "hash_secret" and algo = "argon2-low-level") or
          (attr.getName() = "hash_secret_raw" and algo = "argon2-low-level-raw") or
          (attr.getName() = "verify_secret" and algo = "argon2-low-level-verify")
        )
      )
    )

    or

    // Deprecated module-level APIs: argon2.hash_password(), argon2.hash_password_raw(),
    //                                argon2.verify_password()
    (
      api = "argon2-cffi" and
      (
        (isAttrCall(call, "argon2", "hash_password") and algo = "argon2-hash-password-deprecated") or
        (isAttrCall(call, "argon2", "hash_password_raw") and algo = "argon2-hash-password-raw-deprecated") or
        (isAttrCall(call, "argon2", "verify_password") and algo = "argon2-verify-password-deprecated")
      )
    )

    or

    // =============================================================================
    // passlib — passlib.hash.bcrypt, passlib.hash.argon2, passlib.hash.scrypt, etc.
    // passlib.hash.X.hash(password), passlib.hash.X.verify(password, hash)
    // =============================================================================
    (
      api = "passlib" and
      exists(Attribute method, Attribute scheme |
        call.getFunc() = method and
        method.getObject() = scheme and
        method.getName() = ["hash", "verify", "encrypt", "genconfig", "genhash",
                            "using", "identify"] and
        (
          // bcrypt variants
          (scheme.getName() = "bcrypt"         and algo = "bcrypt") or
          (scheme.getName() = "bcrypt_sha256"  and algo = "bcrypt-sha256") or

          // argon2
          (scheme.getName() = "argon2"         and algo = "argon2") or

          // scrypt
          (scheme.getName() = "scrypt"         and algo = "scrypt") or

          // pbkdf2
          (scheme.getName() = "pbkdf2_sha256"  and algo = "pbkdf2-sha256") or
          (scheme.getName() = "pbkdf2_sha512"  and algo = "pbkdf2-sha512") or
          (scheme.getName() = "pbkdf2_sha1"    and algo = "pbkdf2-sha1") or

          // sha-crypt (Unix)
          (scheme.getName() = "sha256_crypt"   and algo = "sha256-crypt") or
          (scheme.getName() = "sha512_crypt"   and algo = "sha512-crypt") or

          // md5-crypt
          (scheme.getName() = "md5_crypt"      and algo = "md5-crypt") or

          // des-crypt
          (scheme.getName() = "des_crypt"      and algo = "des-crypt") or

          // ldap
          (scheme.getName() = "ldap_sha256_crypt" and algo = "ldap-sha256-crypt") or
          (scheme.getName() = "ldap_sha512_crypt" and algo = "ldap-sha512-crypt") or
          (scheme.getName() = "ldap_bcrypt"       and algo = "ldap-bcrypt") or
          (scheme.getName() = "ldap_pbkdf2_sha256" and algo = "ldap-pbkdf2-sha256") or
          (scheme.getName() = "ldap_pbkdf2_sha512" and algo = "ldap-pbkdf2-sha512") or

          // additional schemes
          (scheme.getName() = "django_pbkdf2_sha256" and algo = "django-pbkdf2-sha256") or
          (scheme.getName() = "django_pbkdf2_sha1"   and algo = "django-pbkdf2-sha1") or
          (scheme.getName() = "django_bcrypt"        and algo = "django-bcrypt") or
          (scheme.getName() = "django_argon2"        and algo = "django-argon2") or
          (scheme.getName() = "phpass"               and algo = "phpass") or
          (scheme.getName() = "mysql_sha1"           and algo = "mysql-sha1") or
          (scheme.getName() = "mysql323"             and algo = "mysql323") or
          (scheme.getName() = "oracle10g"            and algo = "oracle10g") or
          (scheme.getName() = "oracle11"             and algo = "oracle11") or
          (scheme.getName() = "postgres_md5"         and algo = "postgres-md5") or
          (scheme.getName() = "mssql2000"            and algo = "mssql2000") or
          (scheme.getName() = "mssql2005"            and algo = "mssql2005") or
          (scheme.getName() = "nthash"              and algo = "nthash") or
          (scheme.getName() = "lmhash"              and algo = "lmhash") or
          (scheme.getName() = "cisco_type7"         and algo = "cisco-type7") or
          (scheme.getName() = "fshp"                and algo = "fshp") or
          (scheme.getName() = "hex_sha256"          and algo = "hex-sha256") or
          (scheme.getName() = "hex_sha512"          and algo = "hex-sha512") or
          (scheme.getName() = "plaintext"           and algo = "plaintext") or

          // additional hash schemes
          (scheme.getName() = "apr_md5_crypt"       and algo = "apr-md5-crypt") or
          (scheme.getName() = "bigcrypt"            and algo = "bigcrypt") or
          (scheme.getName() = "bsdi_crypt"          and algo = "bsdi-crypt") or
          (scheme.getName() = "bsd_nthash"          and algo = "bsd-nthash") or
          (scheme.getName() = "sha1_crypt"          and algo = "sha1-crypt") or
          (scheme.getName() = "sun_md5_crypt"       and algo = "sun-md5-crypt") or
          (scheme.getName() = "hex_md4"             and algo = "hex-md4") or
          (scheme.getName() = "hex_md5"             and algo = "hex-md5") or
          (scheme.getName() = "hex_sha1"            and algo = "hex-sha1") or
          (scheme.getName() = "ldap_md5"            and algo = "ldap-md5") or
          (scheme.getName() = "ldap_sha1"           and algo = "ldap-sha1") or
          (scheme.getName() = "ldap_salted_md5"     and algo = "ldap-salted-md5") or
          (scheme.getName() = "ldap_salted_sha1"    and algo = "ldap-salted-sha1") or
          (scheme.getName() = "ldap_des_crypt"      and algo = "ldap-des-crypt") or
          (scheme.getName() = "ldap_bsdi_crypt"     and algo = "ldap-bsdi-crypt") or
          (scheme.getName() = "ldap_md5_crypt"      and algo = "ldap-md5-crypt") or
          (scheme.getName() = "ldap_plaintext"      and algo = "ldap-plaintext") or
          (scheme.getName() = "msdcc"               and algo = "msdcc") or
          (scheme.getName() = "msdcc2"              and algo = "msdcc2") or
          (scheme.getName() = "cta_pbkdf2_sha1"     and algo = "cta-pbkdf2-sha1") or
          (scheme.getName() = "dlitz_pbkdf2_sha1"   and algo = "dlitz-pbkdf2-sha1") or
          (scheme.getName() = "grub_pbkdf2_sha512"  and algo = "grub-pbkdf2-sha512") or
          (scheme.getName() = "atlassian_pbkdf2_sha1" and algo = "atlassian-pbkdf2-sha1") or
          (scheme.getName() = "django_des_crypt"    and algo = "django-des-crypt") or
          (scheme.getName() = "django_disabled"     and algo = "django-disabled") or
          (scheme.getName() = "django_salted_md5"   and algo = "django-salted-md5") or
          (scheme.getName() = "django_salted_sha1"  and algo = "django-salted-sha1") or
          (scheme.getName() = "unix_disabled"       and algo = "unix-disabled") or
          (scheme.getName() = "unix_fallback"       and algo = "unix-fallback")
        )
      )
    )

    or

    // passlib.context.CryptContext
    (
      api = "passlib" and
      isConstructorCall(call, "CryptContext") and
      algo = "passlib-context"
    )

    or

    // CryptContext instance methods: ctx.hash(), ctx.verify(), ctx.identify()
    (
      api = "passlib" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = ["hash", "verify", "identify", "encrypt"] and
        (
          attr.getObject().toString().matches("%[Cc]ontext%") or
          attr.getObject().toString().matches("%ctx%") or
          attr.getObject().toString().matches("%pwd%context%")
        )
      ) and
      fileImportsPasslib(call.getLocation().getFile()) and
      algo = "passlib-context-op"
    )

    or

    // =============================================================================
    // passlib.crypto.digest — hash lookup, HMAC, PBKDF1, PBKDF2
    // =============================================================================
    (
      api = "passlib" and
      (
        (isAttrCall(call, "digest", "lookup_hash")    and algo = "passlib-lookup-hash") or
        (isAttrCall(call, "digest", "norm_hash_name") and algo = "passlib-norm-hash-name") or
        (isAttrCall(call, "digest", "compile_hmac")   and algo = "passlib-compile-hmac") or
        (isAttrCall(call, "digest", "pbkdf1")         and algo = "passlib-pbkdf1") or
        (isAttrCall(call, "digest", "pbkdf2_hmac")    and algo = "passlib-pbkdf2-hmac")
      ) and
      fileImportsPasslib(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // passlib.crypto.des — raw DES block encryption
    // =============================================================================
    (
      api = "passlib" and
      (
        (isAttrCall(call, "des", "des_encrypt_block")     and algo = "passlib-des-encrypt-block") or
        (isAttrCall(call, "des", "des_encrypt_int_block") and algo = "passlib-des-encrypt-int-block")
      ) and
      fileImportsPasslib(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // passlib.crypto.scrypt — scrypt KDF wrapper
    // =============================================================================
    (
      api = "passlib" and
      isAttrCall(call, "_scrypt", "scrypt") and
      algo = "passlib-scrypt" and
      fileImportsPasslib(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // passlib.totp — Time-based One-Time Passwords
    // =============================================================================
    (
      api = "passlib" and
      (
        (isConstructorCall(call, "TOTP") and algo = "passlib-totp") or
        (isAttrCall(call, "totp", "TOTP") and algo = "passlib-totp")
      ) and
      fileImportsPasslib(call.getLocation().getFile())
    )

    or

    // TOTP instance methods: t.generate(), t.verify(), t.from_uri(), etc.
    (
      api = "passlib" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = ["generate", "verify", "from_source", "from_uri",
                          "to_uri", "key", "pretty_key"] and
        attr.getObject().toString().matches("%[Tt][Oo][Tt][Pp]%")
      ) and
      fileImportsPasslib(call.getLocation().getFile()) and
      algo = "passlib-totp-op"
    )

    or

    // =============================================================================
    // passlib.apache — HtpasswdFile, HtdigestFile
    // =============================================================================
    (
      api = "passlib" and
      (
        (isConstructorCall(call, "HtpasswdFile") and algo = "passlib-htpasswd") or
        (isConstructorCall(call, "HtdigestFile") and algo = "passlib-htdigest") or
        (isAttrCall(call, "apache", "HtpasswdFile") and algo = "passlib-htpasswd") or
        (isAttrCall(call, "apache", "HtdigestFile") and algo = "passlib-htdigest")
      ) and
      fileImportsPasslib(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // passlib.pwd — secure password/passphrase generation
    // =============================================================================
    (
      api = "passlib" and
      (
        (isAttrCall(call, "pwd", "genword")   and algo = "passlib-genword") or
        (isAttrCall(call, "pwd", "genphrase") and algo = "passlib-genphrase") or
        (exists(Name fn | call.getFunc() = fn and fn.getId() = "genword") and
         algo = "passlib-genword") or
        (exists(Name fn | call.getFunc() = fn and fn.getId() = "genphrase") and
         algo = "passlib-genphrase")
      ) and
      fileImportsPasslib(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // scrypt — standalone scrypt module (hashlib.scrypt or scrypt package)
    // =============================================================================

    // hashlib.scrypt(password, salt=salt, n=n, r=r, p=p)
    (
      isAttrCall(call, "hashlib", "scrypt") and
      algo = "scrypt" and api = "hashlib"
    )

    or

    // scrypt.hash(password, salt, N, r, p)
    (
      isAttrCall(call, "scrypt", "hash") and
      algo = "scrypt" and api = "scrypt"
    )

    or

    // scrypt.encrypt(input, password, ...) and scrypt.decrypt(input, password, ...)
    (
      isAttrCall(call, "scrypt", "encrypt") and
      algo = "scrypt-encrypt" and api = "scrypt"
    )

    or

    (
      isAttrCall(call, "scrypt", "decrypt") and
      algo = "scrypt-decrypt" and api = "scrypt"
    )

    or

    // =============================================================================
    // Django password hashing — django.contrib.auth.hashers
    // =============================================================================
    (
      api = "django" and
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "make_password"  and algo = "django-make-password") or
          (fn.getId() = "check_password" and algo = "django-check-password")
        )
      ) and
      // Guard: file must have Django-related imports
      fileImportsDjango(call.getLocation().getFile())
    )

    or

    (
      api = "django" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%hashers%") and
        (
          (attr.getName() = "make_password"  and algo = "django-make-password") or
          (attr.getName() = "check_password" and algo = "django-check-password")
        )
      )
    )

    or

    // Django hasher classes
    (
      api = "django" and
      (
        (isConstructorCall(call, "PBKDF2PasswordHasher")       and algo = "django-pbkdf2") or
        (isConstructorCall(call, "PBKDF2SHA1PasswordHasher")   and algo = "django-pbkdf2-sha1") or
        (isConstructorCall(call, "Argon2PasswordHasher")       and algo = "django-argon2") or
        (isConstructorCall(call, "BCryptSHA256PasswordHasher") and algo = "django-bcrypt-sha256") or
        (isConstructorCall(call, "BCryptPasswordHasher")       and algo = "django-bcrypt") or
        (isConstructorCall(call, "ScryptPasswordHasher")       and algo = "django-scrypt") or
        (isConstructorCall(call, "MD5PasswordHasher")          and algo = "django-md5") or
        (isConstructorCall(call, "SHA1PasswordHasher")         and algo = "django-sha1") or
        (isConstructorCall(call, "UnsaltedSHA1PasswordHasher") and algo = "django-unsalted-sha1") or
        (isConstructorCall(call, "UnsaltedMD5PasswordHasher")  and algo = "django-unsalted-md5") or
        (isConstructorCall(call, "CryptPasswordHasher")        and algo = "django-crypt")
      )
    )

    or

    // django.contrib.auth.hashers.identify_hasher()
    (
      api = "django" and
      (
        isAttrCall(call, "hashers", "identify_hasher") or
        (
          exists(Name fn | call.getFunc() = fn and fn.getId() = "identify_hasher") and
          fileImportsDjango(call.getLocation().getFile())
        )
      ) and
      algo = "django-identify-hasher"
    )

    or

    // =============================================================================
    // Werkzeug password hashing — werkzeug.security
    // =============================================================================
    (
      api = "werkzeug" and
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "generate_password_hash" and algo = "werkzeug-password-hash") or
          (fn.getId() = "check_password_hash"    and algo = "werkzeug-password-check") or
          (fn.getId() = "safe_str_cmp"           and algo = "werkzeug-safe-str-cmp") or
          (fn.getId() = "gen_salt"               and algo = "werkzeug-gen-salt") or
          (fn.getId() = "pbkdf2_hex"             and algo = "werkzeug-pbkdf2-hex") or
          (fn.getId() = "pbkdf2_bin"             and algo = "werkzeug-pbkdf2-bin")
        )
      )
    )

    or

    (
      api = "werkzeug" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%security%") and
        (
          (attr.getName() = "generate_password_hash" and algo = "werkzeug-password-hash") or
          (attr.getName() = "check_password_hash"    and algo = "werkzeug-password-check") or
          (attr.getName() = "safe_str_cmp"           and algo = "werkzeug-safe-str-cmp") or
          (attr.getName() = "gen_salt"               and algo = "werkzeug-gen-salt") or
          (attr.getName() = "pbkdf2_hex"             and algo = "werkzeug-pbkdf2-hex") or
          (attr.getName() = "pbkdf2_bin"             and algo = "werkzeug-pbkdf2-bin")
        )
      )
    )
  )
select call, "algo=" + algo + ", api=" + api
