"""
Test suite for DjangoCrypto.ql — Django framework crypto usage beyond passwords.
Each call site below should be detected by the query.
"""

# =============================================================================
# django.core.signing — Signer, TimestampSigner, dumps(), loads()
# =============================================================================
from django.core import signing
from django.core.signing import Signer, TimestampSigner

# Signer usage
signer = Signer()
ts_signer = TimestampSigner()

# Module-level signing functions
signed_data = signing.dumps({"user_id": 42})
original = signing.loads(signed_data)

# Signer via attribute
signer2 = signing.Signer()
ts_signer2 = signing.TimestampSigner()

# =============================================================================
# django.utils.crypto — utility functions
# =============================================================================
from django.utils.crypto import get_random_string, constant_time_compare, salted_hmac

# Random string generation (CSPRNG-backed)
token = get_random_string(32)

# Constant-time comparison
is_valid = constant_time_compare(token, "expected_value")

# Salted HMAC
mac = salted_hmac("salt", "value")

# =============================================================================
# CSRF middleware
# =============================================================================
from django.middleware.csrf import CsrfViewMiddleware, get_token, rotate_token

middleware = CsrfViewMiddleware()
csrf_token = get_token(request)
rotate_token(request)

# =============================================================================
# Signed cookies
# =============================================================================
response.set_signed_cookie("name", "value", salt="extra")
value = request.get_signed_cookie("name", salt="extra")

# =============================================================================
# Session store
# =============================================================================
from django.contrib.sessions.backends.signed_cookies import SessionStore

session = SessionStore()

# =============================================================================
# Password reset tokens
# =============================================================================
from django.contrib.auth.tokens import PasswordResetTokenGenerator

token_gen = PasswordResetTokenGenerator()
reset_token = token_gen.make_token(user)
is_valid = token_gen.check_token(user, reset_token)
