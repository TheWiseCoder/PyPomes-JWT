from .jwt_constants import (
    JWT_DB_ENGINE, JWT_DB_HOST, JWT_DB_NAME,
    JWT_DB_PORT, JWT_DB_USER, JWT_DB_PWD,
    JWT_ACCESS_MAX_AGE, JWT_REFRESH_MAX_AGE,
    JWT_ENCODING_KEY, JWT_DECODING_KEY
)
from .jwt_pomes import (
    jwt_needed, jwt_verify_request,
    jwt_get_tokens, jwt_get_claims, jwt_validate_token,
    jwt_assert_access, jwt_set_access, jwt_remove_access, jwt_revoke_tokens
)

__all__ = [
    # jwt_constants
    "JWT_DB_ENGINE", "JWT_DB_HOST", "JWT_DB_NAME",
    "JWT_DB_PORT", "JWT_DB_USER", "JWT_DB_PWD",
    "JWT_ACCESS_MAX_AGE", "JWT_REFRESH_MAX_AGE",
    "JWT_ENCODING_KEY", "JWT_DECODING_KEY",
    # jwt_pomes
    "jwt_needed", "jwt_verify_request",
    "jwt_get_tokens", "jwt_get_claims", "jwt_validate_token",
    "jwt_assert_access", "jwt_set_access", "jwt_remove_access", "jwt_revoke_tokens"
]

from importlib.metadata import version
__version__ = version("pypomes_jwt")
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())
