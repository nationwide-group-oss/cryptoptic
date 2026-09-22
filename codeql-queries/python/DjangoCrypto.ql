/**
 * @name Crypto inventory — Django framework crypto (Python)
 * @description Inventory of Django framework cryptographic usage beyond password
 *              hashing: signing, CSRF, crypto utilities, and session security.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/python-cbom-django-crypto
 * @tags security
 */

import python
import lib.PyCryptoCommon

from Call call, string algo, string api
where
  api = "django" and
  (
    // =============================================================================
    // django.core.signing — Signer, TimestampSigner, dumps(), loads()
    // =============================================================================

    // Signer() / TimestampSigner()
    // Guard: exclude itsdangerous files which also use these constructors
    (
      not fileImportsItsdangerous(call.getLocation().getFile()) and
      (
        (isConstructorCall(call, "Signer") and algo = "django-signer") or
        (isConstructorCall(call, "TimestampSigner") and algo = "django-timestamp-signer")
      )
    )

    or

    // signing.Signer(), signing.TimestampSigner()
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%signing%") and
        (
          (attr.getName() = "Signer"          and algo = "django-signer") or
          (attr.getName() = "TimestampSigner"  and algo = "django-timestamp-signer") or
          (attr.getName() = "dumps"            and algo = "django-signing-dumps") or
          (attr.getName() = "loads"            and algo = "django-signing-loads")
        )
      )
    )

    or

    // Direct calls: from django.core.signing import dumps, loads
    (
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "signing_dumps" and algo = "django-signing-dumps") or
          (fn.getId() = "signing_loads" and algo = "django-signing-loads")
        )
      )
    )

    or

    // =============================================================================
    // django.utils.crypto — get_random_string, constant_time_compare, pbkdf2, salted_hmac
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%crypto%") and
        (
          (attr.getName() = "get_random_string"      and algo = "django-random-string") or
          (attr.getName() = "constant_time_compare"  and algo = "django-constant-compare") or
          (attr.getName() = "pbkdf2"                 and algo = "django-pbkdf2") or
          (attr.getName() = "salted_hmac"            and algo = "django-salted-hmac")
        )
      )
    )

    or

    // Direct imports: from django.utils.crypto import get_random_string
    (
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "get_random_string"     and algo = "django-random-string") or
          (fn.getId() = "constant_time_compare" and algo = "django-constant-compare") or
          (fn.getId() = "salted_hmac"           and algo = "django-salted-hmac")
        )
      )
    )

    or

    // =============================================================================
    // django.middleware.csrf — CSRF token (uses crypto internally)
    // =============================================================================
    (
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "get_token"    and algo = "django-csrf-token") or
          (fn.getId() = "rotate_token" and algo = "django-csrf-rotate")
        )
      ) and
      // Guard: file must have Django-related imports to avoid false positives
      fileImportsDjango(call.getLocation().getFile())
    )

    or

    // CsrfViewMiddleware
    (isConstructorCall(call, "CsrfViewMiddleware") and algo = "django-csrf-middleware")

    or

    // =============================================================================
    // django.contrib.auth.tokens — PasswordResetTokenGenerator
    // =============================================================================
    (
      isConstructorCall(call, "PasswordResetTokenGenerator") and
      algo = "django-password-reset-token"
    )

    or

    // PasswordResetTokenGenerator instance methods
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = ["make_token", "check_token"] and
        (
          attr.getObject().toString().matches("%token%generator%") or
          attr.getObject().toString().matches("%token_generator%")
        )
      ) and
      fileImportsDjango(call.getLocation().getFile()) and
      algo = "django-password-reset-token-op"
    )

    or

    // =============================================================================
    // django.contrib.sessions — session backends
    // =============================================================================
    (
      isConstructorCall(call, "SessionStore") and algo = "django-session-store"
    )

    or

    // =============================================================================
    // django signed cookies — response.set_signed_cookie / request.get_signed_cookie
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "set_signed_cookie" and algo = "django-signed-cookie") or
          (attr.getName() = "get_signed_cookie" and algo = "django-signed-cookie-read")
        )
      )
    )

    or

    // =============================================================================
    // django.core.signing — Signer/TimestampSigner instance methods
    // =============================================================================
    (
      not fileImportsItsdangerous(call.getLocation().getFile()) and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "sign"          and algo = "django-signer-sign") or
          (attr.getName() = "unsign"        and algo = "django-signer-unsign") or
          (attr.getName() = "sign_object"   and algo = "django-signer-sign-object") or
          (attr.getName() = "unsign_object" and algo = "django-signer-unsign-object")
        ) and
        (
          attr.getObject().toString().matches("%[Ss]igner%") or
          attr.getObject().toString().matches("%[Tt]imestamp%")
        )
      ) and
      fileImportsDjango(call.getLocation().getFile())
    )

    or

    // =============================================================================
    // django.core.management.utils — get_random_secret_key()
    // =============================================================================
    (
      (
        isAttrCall(call, "utils", "get_random_secret_key") or
        exists(Name fn | call.getFunc() = fn and fn.getId() = "get_random_secret_key")
      ) and
      fileImportsDjango(call.getLocation().getFile()) and
      algo = "django-get-random-secret-key"
    )

    or

    // =============================================================================
    // django.contrib.auth.hashers — identify_hasher()
    // =============================================================================
    (
      (
        isAttrCall(call, "hashers", "identify_hasher") or
        exists(Name fn | call.getFunc() = fn and fn.getId() = "identify_hasher")
      ) and
      fileImportsDjango(call.getLocation().getFile()) and
      algo = "django-identify-hasher"
    )

    or

    // =============================================================================
    // django.contrib.auth.hashers — additional hasher classes
    // =============================================================================
    (
      (
        (isConstructorCall(call, "MD5PasswordHasher")         and algo = "django-md5-hasher") or
        (isConstructorCall(call, "SHA1PasswordHasher")        and algo = "django-sha1-hasher") or
        (isConstructorCall(call, "UnsaltedSHA1PasswordHasher") and algo = "django-unsalted-sha1-hasher") or
        (isConstructorCall(call, "UnsaltedMD5PasswordHasher")  and algo = "django-unsalted-md5-hasher") or
        (isConstructorCall(call, "CryptPasswordHasher")       and algo = "django-crypt-hasher")
      )
    )

    or

    // =============================================================================
    // django.contrib.auth.models — User.set_password() / User.check_password()
    // =============================================================================
    (
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          (attr.getName() = "set_password"   and algo = "django-user-set-password") or
          (attr.getName() = "check_password" and algo = "django-user-check-password")
        ) and
        (
          attr.getObject().toString().matches("%[Uu]ser%") or
          attr.getObject().toString().matches("%account%") or
          attr.getObject().toString().matches("%self%")
        )
      ) and
      fileImportsDjango(call.getLocation().getFile())
    )

  )
select call, "algo=" + algo + ", api=" + api
