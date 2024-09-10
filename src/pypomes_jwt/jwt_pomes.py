from logging import Logger
from pypomes_core import APP_PREFIX, env_get_str, env_get_bytes, env_get_int
from pypomes_crypto import crypto_generate_rsa_keys
from secrets import token_bytes
from typing import Any, Final, Literal

from .jwt_data import JwtData, _set_base_url, _validate_token

JWT_ACCESS_MAX_AGE: Final[int] = env_get_int(key=f"{APP_PREFIX}JWT_ACCESS_MAX_AGE",
                                             def_value=3600)
JWT_REFRESH_MAX_AGE: Final[int] = env_get_int(key=f"{APP_PREFIX}_JWT_REFRESH_MAX_AGE",
                                              def_value=43200)
JWT_HS_SECRET_KEY: Final[bytes] = env_get_bytes(key=f"{APP_PREFIX}JWT_HS_SECRET_KEY",
                                                def_value=token_bytes(32))

__priv_key: str = env_get_str(key=f"{APP_PREFIX}JWT_RSA_PRIVATE_KEY")
__pub_key: str = env_get_str(key=f"{APP_PREFIX}JWT_RSA_PUBLIC_KEY")
if not __priv_key or not __pub_key:
    (__priv_key, __pub_key) = crypto_generate_rsa_keys(key_size=2048)
JWT_RSA_PRIVATE_KEY: Final[str] = __priv_key
JWT_RSA_PUBLIC_KEY: Final[str] = __pub_key

# the JWT data object
__jwt_data: JwtData | None = None


def jwt_initialize(base_url: str) -> None:
    """
    Initialize the JWT service, and identify its invoking base URL.

    Only the first invocation of the function will be considered.

    :param base_url: the base URL for invoking this service
    """
    global __jwt_data
    if not __jwt_data:
        __jwt_data = JwtData()
        _set_base_url(base_url=base_url)


def jwt_set_service_access(claims: dict[str, Any],
                           service_url: str,
                           service_tag: str = None,
                           auth_type: Literal["HS256", "HS512", "RSA256", "RSA512"] = "HS256",
                           access_max_age: int = JWT_ACCESS_MAX_AGE,
                           refresh_max_age: int = JWT_REFRESH_MAX_AGE,
                           secret_key: bytes = JWT_HS_SECRET_KEY,
                           private_key: str = JWT_RSA_PRIVATE_KEY,
                           public_key: str = JWT_RSA_PUBLIC_KEY,
                           request_timeout: int = None,
                           logger: Logger = None) -> None:
    """
    Set the data needed to obtain JWT tokens from *service_url*.

    :param claims: the JWT claimset, as key-value pairs
    :param service_url: the reference URL
    :param service_tag: element in the path, uniquely identifying the service
    :param auth_type: the authentication type
    :param access_max_age: token duration, in seconds
    :param refresh_max_age: duration for the refresh operation, in seconds
    :param secret_key: secret key for HS authentication
    :param private_key: private key for RSA authentication
    :param public_key: public key for RSA authentication
    :param request_timeout: timeout for the requests to the service URL
    :param logger: optional logger
    """
    __jwt_data.add_access_data(claims=claims,
                               service_url=service_url,
                               service_tag=service_tag,
                               auth_type=auth_type,
                               access_max_age=access_max_age,
                               refresh_max_age=refresh_max_age,
                               secret_key=secret_key,
                               private_key=private_key,
                               public_key=public_key,
                               request_timeout=request_timeout,
                               logger=logger)


def jwt_remove_service_access(service_url: str,
                              logger: Logger = None) -> None:
    """
    Remove from storage the access data for *service_url*.

    :param service_url: the reference URL
    :param logger: optional logger
    """
    __jwt_data.remove_access_data(service_url=service_url,
                                  logger=logger)


def jwt_get_token(errors: list[str],
                  service_url: str,
                  logger: Logger = None) -> str:
    """
    Obtain and return a JWT token from *service_url*.

    :param errors: incidental error messages
    :param service_url: the reference URL
    :param logger: optional logger
    :return: the JWT token, or 'None' if an error ocurred
    """
    # inicialize the return variable
    result: str | None = None

    try:
        result = __jwt_data.get_token(service_url=service_url,
                                      logger=logger)
    except Exception as e:
        if logger:
            logger.error(msg=repr(e))
        errors.append(repr(e))

    return result


def jwt_validate_token(errors: list[str],
                       token: str,
                       logger: Logger = None) -> dict[str, Any]:
    """
    Validate the JWT *token*, and return its claimset.

    :param errors: incidental error messages
    :param token: the token to be validated
    :param logger: optional logger
    :return: the token's claimset, or 'None' if error
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    try:
        result = _validate_token(token=token)
    except Exception as e:
        if logger:
            logger.error(msg=repr(e))
        errors.append(repr(e))

    return result
