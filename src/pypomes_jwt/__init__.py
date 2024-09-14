from .jwt_pomes import (
    JWT_ENDPOINT_URL, JWT_ACCESS_MAX_AGE, JWT_REFRESH_MAX_AGE,
    JWT_HS_SECRET_KEY, JWT_RSA_PRIVATE_KEY, JWT_RSA_PUBLIC_KEY,
    jwt_get_token, jwt_get_token_data,
    jwt_get_claims, jwt_verify_request,
    jwt_service, jwt_set_service_access, jwt_remove_service_access
)

__all__ = [
    # access_pomes
    "JWT_ENDPOINT_URL", "JWT_ACCESS_MAX_AGE", "JWT_REFRESH_MAX_AGE",
    "JWT_HS_SECRET_KEY", "JWT_RSA_PRIVATE_KEY", "JWT_RSA_PUBLIC_KEY",
    "jwt_get_token", "jwt_get_token_data",
    "jwt_get_claims", "jwt_verify_request",
    "jwt_service", "jwt_set_service_access", "jwt_remove_service_access"
]

from importlib.metadata import version
__version__ = version("pypomes_jwt")
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())
