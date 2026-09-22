"""
Test suite for FlaskGunicorn.ql — Flask & Gunicorn crypto usage.
Each call site below should be detected by the query.
"""

# =============================================================================
# Flask — Application and session security
# =============================================================================
from flask import Flask

app = Flask(__name__)

# Flask app.run with SSL
app.run(ssl_context=("cert.pem", "key.pem"))
app.run(ssl_context="adhoc")

# =============================================================================
# Flask-WTF CSRF
# =============================================================================
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# =============================================================================
# Flask-Bcrypt
# =============================================================================
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)
pw_hash = bcrypt.generate_password_hash("password")
is_correct = bcrypt.check_password_hash(pw_hash, "password")

# =============================================================================
# Flask-Login — session management
# =============================================================================
from flask_login import LoginManager

login_manager = LoginManager()
login_manager.init_app(app)

# =============================================================================
# Flask-Talisman — HTTPS enforcement & security headers
# =============================================================================
from flask_talisman import Talisman

talisman = Talisman(app)

# =============================================================================
# Flask-SSLify
# =============================================================================
from flask_sslify import SSLify

sslify = SSLify(app)

# =============================================================================
# Flask-JWT-Extended
# =============================================================================
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token

jwt = JWTManager(app)
access = create_access_token(identity="user")
refresh = create_refresh_token(identity="user")

# =============================================================================
# Flask-CORS
# =============================================================================
from flask_cors import CORS

cors = CORS(app)

# =============================================================================
# Flask secure session interface
# =============================================================================
from flask.sessions import SecureCookieSessionInterface

session_interface = SecureCookieSessionInterface()

# =============================================================================
# Gunicorn — TLS/SSL configuration
# =============================================================================
from gunicorn.app.base import BaseApplication
from gunicorn.app.wsgiapp import WSGIApplication
from gunicorn.arbiter import Arbiter


# Programmatic Gunicorn app
class MyApp(BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        # TLS configuration
        self.cfg.set("certfile", "/path/to/cert.pem")
        self.cfg.set("keyfile", "/path/to/key.pem")
        self.cfg.set("ssl_version", 5)
        self.cfg.set("ciphers", "TLS_AES_256_GCM_SHA384")

    def load(self):
        return self.application


gunicorn_app = BaseApplication()
wsgi_app = WSGIApplication()

# Arbiter (manages worker processes with TLS)
arbiter = Arbiter(gunicorn_app)

# SSL context for Gunicorn
import ssl

ctx = ssl.create_default_context()

# =============================================================================
# Flask-Security — authentication with crypto
# =============================================================================
from flask_security import Security, SQLAlchemyUserDatastore

security = Security()
security.init_app(app)
user_datastore = SQLAlchemyUserDatastore(db, User, Role)

# =============================================================================
# Flask-Session — server-side sessions
# =============================================================================
from flask_session import Session
from flask_session.redis import RedisSessionInterface
from flask_session.memcached import MemcachedSessionInterface

sess = Session(app)
redis_iface = RedisSessionInterface()
memcached_iface = MemcachedSessionInterface()

# =============================================================================
# Gunicorn — TLS config via keyword arguments
# =============================================================================
gunicorn_tls_app = BaseApplication(
    keyfile="/path/to/key.pem",
    certfile="/path/to/cert.pem",
    ca_certs="/path/to/ca-bundle.crt",
    ssl_version=5,
    ciphers="TLS_AES_256_GCM_SHA384",
    cert_reqs=2,
    do_handshake_on_connect=True,
    suppress_ragged_eofs=True,
    ssl_context=my_ssl_context_hook,
)


# Gunicorn config.set with additional params
class MyApp2(BaseApplication):
    def load_config(self):
        self.cfg.set("ca_certs", "/path/to/ca-bundle.crt")
        self.cfg.set("cert_reqs", 2)
        self.cfg.set("do_handshake_on_connect", True)
        self.cfg.set("suppress_ragged_eofs", True)
        self.cfg.set("ssl_context", "my_ssl_context_hook")

    def load(self):
        return self.application


# =============================================================================
# Flask-HTTPAuth — HTTP authentication
# =============================================================================
from flask_httpauth import HTTPBasicAuth, HTTPDigestAuth, HTTPTokenAuth, MultiAuth

basic_auth = HTTPBasicAuth()
digest_auth = HTTPDigestAuth()
token_auth = HTTPTokenAuth(scheme="Bearer")
multi_auth = MultiAuth(basic_auth, token_auth)

# =============================================================================
# Flask-Paranoid — session fixation protection
# =============================================================================
from flask_paranoid import Paranoid

paranoid = Paranoid(app)

# =============================================================================
# Flask-OIDC — OpenID Connect
# =============================================================================
from flask_oidc import OpenIDConnect

oidc = OpenIDConnect(app)

# =============================================================================
# Flask-Dance — OAuth
# =============================================================================
from flask_dance.contrib.github import make_github_blueprint
from flask_dance.contrib.google import make_google_blueprint
from flask_dance.consumer import OAuth2ConsumerBlueprint, OAuth1ConsumerBlueprint

github_bp = make_github_blueprint(client_id="id", client_secret="secret")
google_bp = make_google_blueprint(client_id="id", client_secret="secret")
custom_oauth2 = OAuth2ConsumerBlueprint(
    "custom", __name__, client_id="id", client_secret="secret"
)
custom_oauth1 = OAuth1ConsumerBlueprint(
    "custom", __name__, client_key="key", client_secret="secret"
)

# =============================================================================
# Flask-Praetorian — JWT-based authentication
# =============================================================================
from flask_praetorian import Praetorian

guard = Praetorian()
guard.init_app(app)
guard.authenticate("user", "pass")
token = guard.encode_jwt_token(user)
data = guard.decode_jwt_token(token)
refreshed = guard.refresh_jwt_token(token)
read = guard.read_token()
hashed = guard.hash_password("password")
verified = guard.verify_password("password", hashed)
