/**
 * @name Crypto inventory — Flask & Gunicorn (Python)
 * @description Inventory of Flask framework and Gunicorn server cryptographic
 *              usage including session security, CSRF, TLS configuration, and
 *              crypto extensions.
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id local/python-cbom-flask-gunicorn
 * @tags security
 */

import python
import lib.PyCryptoCommon

from Call call, string algo, string api
where
  (
    // =============================================================================
    // Flask — Session security & crypto
    // =============================================================================

    // Flask-WTF CSRF protection
    (
      api = "flask" and
      (
        (isConstructorCall(call, "CSRFProtect") and algo = "flask-csrf-protect") or
        (isConstructorCall(call, "CsrfProtect") and algo = "flask-csrf-protect")
      )
    )

    or

    // Flask-Bcrypt
    (
      api = "flask-bcrypt" and
      (
        (isConstructorCall(call, "Bcrypt") and algo = "flask-bcrypt-init") or
        (
          exists(Attribute attr |
            call.getFunc() = attr and
            (
              (attr.getName() = "generate_password_hash" and algo = "flask-bcrypt-hash") or
              (attr.getName() = "check_password_hash"    and algo = "flask-bcrypt-check")
            ) and
            // Guard: receiver should reference bcrypt instance
            (
              attr.getObject().toString().matches("%bcrypt%") or
              attr.getObject().toString().matches("%Bcrypt%")
            )
          )
        )
      )
    )

    or

    // Flask-Login — session management (uses crypto for session tokens)
    (
      api = "flask" and
      (
        (isConstructorCall(call, "LoginManager") and algo = "flask-login-manager") or
        (
          exists(Attribute attr |
            call.getFunc() = attr and
            attr.getName() = "init_app" and
            attr.getObject().toString().matches("%[Ll]ogin%") and
            algo = "flask-login-init"
          )
        )
      )
    )

    or

    // Flask-Talisman — HTTPS/security headers
    (
      api = "flask" and
      (
        (isConstructorCall(call, "Talisman") and algo = "flask-talisman") or
        (
          exists(Attribute attr |
            call.getFunc() = attr and
            attr.getObject().toString().matches("%[Tt]alisman%") and
            attr.getName() = "init_app" and
            algo = "flask-talisman-init"
          )
        )
      )
    )

    or

    // Flask-SSLify
    (
      api = "flask" and
      isConstructorCall(call, "SSLify") and algo = "flask-sslify"
    )

    or

    // Flask session interface
    (
      api = "flask" and
      (
        (isConstructorCall(call, "SecureCookieSessionInterface") and algo = "flask-secure-session") or
        (isConstructorCall(call, "SecureCookieSession") and algo = "flask-secure-cookie-session")
      )
    )

    or

    // Flask.secret_key is typically an assignment, but Flask(secret_key=...) or
    // app.config['SECRET_KEY'] patterns don't produce Call nodes.
    // Detect Flask(__name__) constructor for context.
    (
      api = "flask" and
      isConstructorCall(call, "Flask") and algo = "flask-app"
    )

    or

    // flask_jwt_extended / flask-jwt
    (
      api = "flask-jwt" and
      (
        (isConstructorCall(call, "JWTManager") and algo = "flask-jwt-manager") or
        (
          exists(Attribute attr |
            call.getFunc() = attr and
            (
              (attr.getName() = "create_access_token"  and algo = "flask-jwt-access-token") or
              (attr.getName() = "create_refresh_token" and algo = "flask-jwt-refresh-token") or
              (attr.getName() = "decode_token"         and algo = "flask-jwt-decode")
            )
          )
        )
      )
    )

    or

    // flask-cors (CORS with credentials involves secure cookie handling)
    (
      api = "flask" and
      isConstructorCall(call, "CORS") and algo = "flask-cors"
    )

    or

    // =============================================================================
    // Flask-Security — authentication with crypto
    // =============================================================================
    (
      api = "flask-security" and
      (
        (isConstructorCall(call, "Security") and algo = "flask-security-init") or
        (
          exists(Attribute attr |
            call.getFunc() = attr and
            attr.getObject().toString().matches("%[Ss]ecurity%") and
            attr.getName() = "init_app" and
            algo = "flask-security-init-app"
          )
        ) or
        (isConstructorCall(call, "SQLAlchemyUserDatastore") and algo = "flask-security-datastore")
      )
    )

    or

    // =============================================================================
    // Flask-Session — server-side sessions (Redis, Memcached, etc.)
    // =============================================================================
    (
      api = "flask-session" and
      (
        (isConstructorCall(call, "Session") and
         // Guard: avoid matching generic Session names
         (
           call.getLocation().getFile().toString().matches("%flask%") or
           exists(Name n |
             n.getLocation().getFile() = call.getLocation().getFile() and
             (n.getId() = "Flask" or n.getId() = "flask_session")
           )
         ) and
         algo = "flask-session-init") or
        (isConstructorCall(call, "RedisSessionInterface") and algo = "flask-session-redis") or
        (isConstructorCall(call, "MemcachedSessionInterface") and algo = "flask-session-memcached")
      )
    )

    or

    // =============================================================================
    // Gunicorn — TLS/SSL configuration
    // =============================================================================

    // Gunicorn programmatic configuration
    // gunicorn.app.base.BaseApplication or gunicorn.app.wsgiapp.WSGIApplication
    (
      api = "gunicorn" and
      (
        (isConstructorCall(call, "BaseApplication") and algo = "gunicorn-app") or
        (isConstructorCall(call, "WSGIApplication") and algo = "gunicorn-wsgi-app")
      )
    )

    or

    // gunicorn.config — SSL/TLS settings via programmatic config
    (
      api = "gunicorn" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getObject().toString().matches("%gunicorn%") and
        (
          (attr.getName() = "run" and algo = "gunicorn-run")
        )
      )
    )

    or

    // Gunicorn arbiter (starts TLS workers)
    (
      api = "gunicorn" and
      isConstructorCall(call, "Arbiter") and algo = "gunicorn-arbiter"
    )

    or

    // Gunicorn TLS config parameters — detected as keyword arguments in config/run calls
    // or as attribute assignments on config objects
    (
      api = "gunicorn" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          attr.getObject().toString().matches("%gunicorn%") or
          attr.getObject().toString().matches("%config%") or
          attr.getObject().toString().matches("%cfg%")
        ) and
        (
          (attr.getName() = "set" and
            exists(StringLiteral key |
              call.getPositionalArg(0) = key and
              (
                (key.getText() = "keyfile"     and algo = "gunicorn-tls-keyfile") or
                (key.getText() = "certfile"    and algo = "gunicorn-tls-certfile") or
                (key.getText() = "ca_certs"    and algo = "gunicorn-tls-ca-certs") or
                (key.getText() = "ssl_version" and algo = "gunicorn-tls-ssl-version") or
                (key.getText() = "ciphers"     and algo = "gunicorn-tls-ciphers") or
                (key.getText() = "cert_reqs"   and algo = "gunicorn-tls-cert-reqs") or
                (key.getText() = "do_handshake_on_connect" and algo = "gunicorn-tls-handshake-on-connect") or
                (key.getText() = "suppress_ragged_eofs"    and algo = "gunicorn-tls-suppress-ragged-eofs")
              )
            )
          )
        )
      )
    )

    or

    // Gunicorn TLS params as keyword arguments in run/BaseApplication/WSGIApplication calls
    (
      api = "gunicorn" and
      exists(Keyword kw |
        call.getAKeyword() = kw and
        (
          (kw.getArg() = "keyfile"     and algo = "gunicorn-tls-keyfile") or
          (kw.getArg() = "certfile"    and algo = "gunicorn-tls-certfile") or
          (kw.getArg() = "ca_certs"    and algo = "gunicorn-tls-ca-certs") or
          (kw.getArg() = "ssl_version" and algo = "gunicorn-tls-ssl-version") or
          (kw.getArg() = "ciphers"     and algo = "gunicorn-tls-ciphers") or
          (kw.getArg() = "cert_reqs"   and algo = "gunicorn-tls-cert-reqs") or
          (kw.getArg() = "do_handshake_on_connect" and algo = "gunicorn-tls-handshake-on-connect") or
          (kw.getArg() = "suppress_ragged_eofs"    and algo = "gunicorn-tls-suppress-ragged-eofs")
        )
      ) and
      (
        isConstructorCall(call, "BaseApplication") or
        isConstructorCall(call, "WSGIApplication") or
        exists(Attribute attr |
          call.getFunc() = attr and
          attr.getObject().toString().matches("%gunicorn%")
        )
      )
    )

    or

    // Gunicorn ssl_context hook (Gunicorn 21.0+) — callable that customizes SSL context
    // Detected as a keyword argument named "ssl_context" in Gunicorn app/config calls
    (
      api = "gunicorn" and
      exists(Keyword kw |
        call.getAKeyword() = kw and
        kw.getArg() = "ssl_context"
      ) and
      (
        isConstructorCall(call, "BaseApplication") or
        isConstructorCall(call, "WSGIApplication") or
        exists(Attribute attr |
          call.getFunc() = attr and
          attr.getObject().toString().matches("%gunicorn%")
        )
      ) and
      algo = "gunicorn-ssl-context-hook"
    )

    or

    // Gunicorn ssl_context config via .set()
    (
      api = "gunicorn" and
      exists(Attribute attr |
        call.getFunc() = attr and
        (
          attr.getObject().toString().matches("%gunicorn%") or
          attr.getObject().toString().matches("%config%") or
          attr.getObject().toString().matches("%cfg%")
        ) and
        attr.getName() = "set" and
        exists(StringLiteral key |
          call.getPositionalArg(0) = key and
          key.getText() = "ssl_context"
        )
      ) and
      algo = "gunicorn-ssl-context-hook"
    )

    or

    // Flask app.run(ssl_context=...) — often used in development
    (
      api = "flask" and
      exists(Attribute attr |
        call.getFunc() = attr and
        attr.getName() = "run" and
        exists(Keyword kw |
          call.getAKeyword() = kw and
          kw.getArg() = "ssl_context"
        ) and
        algo = "flask-run-ssl"
      )
    )

    or

    // =============================================================================
    // Flask-HTTPAuth — HTTP authentication (digest auth uses challenge-response)
    // =============================================================================
    (
      api = "flask-httpauth" and
      (
        (isConstructorCall(call, "HTTPBasicAuth") and algo = "flask-httpauth-basic") or
        (isConstructorCall(call, "HTTPDigestAuth") and algo = "flask-httpauth-digest") or
        (isConstructorCall(call, "HTTPTokenAuth") and algo = "flask-httpauth-token") or
        (isConstructorCall(call, "MultiAuth") and algo = "flask-httpauth-multi")
      )
    )

    or

    // =============================================================================
    // Flask-Paranoid — session fixation protection
    // =============================================================================
    (
      api = "flask-paranoid" and
      (
        (isConstructorCall(call, "Paranoid") and algo = "flask-paranoid-init") or
        (
          exists(Attribute attr |
            call.getFunc() = attr and
            attr.getObject().toString().matches("%[Pp]aranoid%") and
            attr.getName() = "init_app" and
            algo = "flask-paranoid-init-app"
          )
        )
      )
    )

    or

    // =============================================================================
    // Flask-OIDC — OpenID Connect (token validation, crypto signatures)
    // =============================================================================
    (
      api = "flask-oidc" and
      (
        (isConstructorCall(call, "OpenIDConnect") and algo = "flask-oidc-init") or
        (
          exists(Attribute attr |
            call.getFunc() = attr and
            attr.getObject().toString().matches("%oidc%") and
            (
              (attr.getName() = "init_app" and algo = "flask-oidc-init-app") or
              (attr.getName() = "validate_token" and algo = "flask-oidc-validate-token")
            )
          )
        )
      )
    )

    or

    // =============================================================================
    // Flask-Dance — OAuth (token exchange, crypto signatures)
    // =============================================================================
    (
      api = "flask-dance" and
      exists(Name fn |
        call.getFunc() = fn and
        (
          (fn.getId() = "make_github_blueprint"    and algo = "flask-dance-github") or
          (fn.getId() = "make_google_blueprint"    and algo = "flask-dance-google") or
          (fn.getId() = "make_facebook_blueprint"  and algo = "flask-dance-facebook") or
          (fn.getId() = "make_twitter_blueprint"   and algo = "flask-dance-twitter") or
          (fn.getId() = "make_azure_blueprint"     and algo = "flask-dance-azure") or
          (fn.getId() = "make_gitlab_blueprint"    and algo = "flask-dance-gitlab") or
          (fn.getId() = "make_slack_blueprint"     and algo = "flask-dance-slack")
        )
      )
    )

    or

    // Flask-Dance — OAuth2ConsumerBlueprint / OAuth1ConsumerBlueprint
    (
      api = "flask-dance" and
      (
        (isConstructorCall(call, "OAuth2ConsumerBlueprint") and algo = "flask-dance-oauth2") or
        (isConstructorCall(call, "OAuth1ConsumerBlueprint") and algo = "flask-dance-oauth1")
      )
    )

    or

    // =============================================================================
    // Flask-Praetorian — JWT-based authentication for Flask APIs
    // =============================================================================
    (
      api = "flask-praetorian" and
      (
        (isConstructorCall(call, "Praetorian") and algo = "flask-praetorian-init") or
        (
          exists(Attribute attr |
            call.getFunc() = attr and
            attr.getObject().toString().matches("%[Pp]raetorian%") and
            (
              (attr.getName() = "init_app"            and algo = "flask-praetorian-init-app") or
              (attr.getName() = "authenticate"        and algo = "flask-praetorian-authenticate") or
              (attr.getName() = "encode_jwt_token"    and algo = "flask-praetorian-encode-jwt") or
              (attr.getName() = "decode_jwt_token"    and algo = "flask-praetorian-decode-jwt") or
              (attr.getName() = "refresh_jwt_token"   and algo = "flask-praetorian-refresh-jwt") or
              (attr.getName() = "read_token"          and algo = "flask-praetorian-read-token") or
              (attr.getName() = "hash_password"       and algo = "flask-praetorian-hash-password") or
              (attr.getName() = "verify_password"     and algo = "flask-praetorian-verify-password")
            )
          )
        )
      )
    )
  )
select call, "algo=" + algo + ", api=" + api
