from .jwt_pomes import (
    jwt_set_service_access, jwt_remove_service_access,
    jwt_get_token, jwt_validate_token
)

__all__ = [
    # access_pomes
    "jwt_set_service_access", "jwt_remove_service_access",
    "jwt_get_token", "jwt_validate_token"
]

from importlib.metadata import version
__version__ = version("pypomes_jwt")
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())
