from .jwt_constants import (
    JWT_DB_ENGINE, JWT_DB_HOST, JWT_DB_NAME,
    JWT_DB_PORT, JWT_DB_USER, JWT_DB_PWD,
    JWT_DB_TABLE, JWT_DB_COL_KID, JWT_DB_COL_ACCOUNT,
    JWT_DB_COL_ALGORITHM, JWT_DB_COL_DECODER, JWT_DB_COL_TOKEN,
    JWT_ACCESS_MAX_AGE, JWT_REFRESH_MAX_AGE,
    JWT_ENCODING_KEY, JWT_DECODING_KEY
)
from .jwt_pomes import (
    jwt_needed, jwt_verify_request,
    jwt_assert_account, jwt_set_account, jwt_remove_account,
    jwt_get_tokens, jwt_get_claims, jwt_validate_token, jwt_revoke_token
)

__all__ = [
    # jwt_constants
    "JWT_DB_ENGINE", "JWT_DB_HOST", "JWT_DB_NAME",
    "JWT_DB_PORT", "JWT_DB_USER", "JWT_DB_PWD",
    "JWT_DB_TABLE", "JWT_DB_COL_KID", "JWT_DB_COL_ACCOUNT",
    "JWT_DB_COL_ALGORITHM", "JWT_DB_COL_DECODER", "JWT_DB_COL_TOKEN",
    "JWT_ACCESS_MAX_AGE", "JWT_REFRESH_MAX_AGE",
    "JWT_ENCODING_KEY", "JWT_DECODING_KEY",
    # jwt_pomes
    "jwt_needed", "jwt_verify_request",
    "jwt_assert_account", "jwt_set_account", "jwt_remove_account",
    "jwt_get_tokens", "jwt_get_claims", "jwt_validate_token", "jwt_revoke_token"
]

from importlib.metadata import version
__version__ = version("pypomes_jwt")
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())
