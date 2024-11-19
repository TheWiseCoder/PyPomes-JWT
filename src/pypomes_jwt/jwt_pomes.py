import contextlib
from flask import Request, Response, request, jsonify
from logging import Logger
from OpenSSL import crypto
from pypomes_core import APP_PREFIX, env_get_str, env_get_bytes, env_get_int
from secrets import token_bytes
from typing import Any, Final, Literal

from .jwt_data import JwtData, jwt_validate_token

JWT_DEFAULT_ALGORITHM: Final[str] = env_get_str(key=f"{APP_PREFIX}_JWT_DEFAULT_ALGORITHM",
                                                def_value="HS256")
JWT_ACCESS_MAX_AGE: Final[int] = env_get_int(key=f"{APP_PREFIX}_JWT_ACCESS_MAX_AGE",
                                             def_value=3600)
JWT_REFRESH_MAX_AGE: Final[int] = env_get_int(key=f"{APP_PREFIX}_JWT_REFRESH_MAX_AGE",
                                              def_value=43200)
JWT_HS_SECRET_KEY: Final[bytes] = env_get_bytes(key=f"{APP_PREFIX}_JWT_HS_SECRET_KEY",
                                                def_value=token_bytes(32))
# must point to 'jwt_service()' below
JWT_ENDPOINT_URL: Final[str] = env_get_str(key=f"{APP_PREFIX}_JWT_ENDPOINT_URL")

__priv_key: bytes = env_get_bytes(key=f"{APP_PREFIX}_JWT_RSA_PRIVATE_KEY")
__pub_key: bytes = env_get_bytes(key=f"{APP_PREFIX}_JWT_RSA_PUBLIC_KEY")
if not __priv_key or not __pub_key:
    pk = crypto.PKey()
    __priv_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pk)
    __pub_key = crypto.dump_publickey(crypto.FILETYPE_PEM, pk)
JWT_RSA_PRIVATE_KEY: Final[bytes] = __priv_key
JWT_RSA_PUBLIC_KEY: Final[bytes] = __pub_key

# the JWT data object
__jwt_data: JwtData = JwtData()


def jwt_needed(func: callable) -> callable:
    """
    Create a decorator to authenticate service endpoints with JWT tokens.

    :param func: the function being decorated
    """
    # ruff: noqa: ANN003
    def wrapper(*args, **kwargs) -> Response:
        response: Response = jwt_verify_request(request=request) if JWT_ENDPOINT_URL else None
        return response if response else func(*args, **kwargs)

    # prevent a rogue error ("View function mapping is overwriting an existing endpoint function")
    wrapper.__name__ = func.__name__

    return wrapper


def jwt_set_service_access(service_url: str,
                           claims: dict[str, Any],
                           algorithm: Literal["HS256", "HS512", "RSA256", "RSA512"] = JWT_DEFAULT_ALGORITHM,
                           access_max_age: int = JWT_ACCESS_MAX_AGE,
                           refresh_max_age: int = JWT_REFRESH_MAX_AGE,
                           secret_key: bytes = JWT_HS_SECRET_KEY,
                           private_key: bytes = JWT_RSA_PRIVATE_KEY,
                           public_key: bytes = JWT_RSA_PUBLIC_KEY,
                           request_timeout: int = None,
                           local_provider: bool = False,
                           logger: Logger = None) -> None:
    """
    Set the data needed to obtain JWT tokens from *service_url*.

    Protocol indication in *service_url* (typically *http:* or *https:*), is disregarded, to guarantee
    that processing herein will not be affected by in-transit protocol changes.

    :param service_url: the reference URL
    :param claims: the JWT claimset, as key-value pairs
    :param algorithm: the authentication type
    :param access_max_age: token duration, in seconds
    :param refresh_max_age: duration for the refresh operation, in seconds
    :param secret_key: secret key for HS authentication
    :param private_key: private key for RSA authentication
    :param public_key: public key for RSA authentication
    :param request_timeout: timeout for the requests to the service URL
    :param local_provider: whether 'service_url' is a local endpoint
    :param logger: optional logger
    """
    # extract the extra claims
    pos: int = service_url.find("?")
    if pos > 0:
        if not local_provider:
            params: list[str] = service_url[pos+1:].split(sep="&")
            for param in params:
                claims[param.split("=")[0]] = param.split("=")[1]
        service_url = service_url[:pos]

    # register the JWT service
    __jwt_data.add_access_data(service_url=service_url,
                               claims=claims,
                               algorithm=algorithm,
                               access_max_age=access_max_age,
                               refresh_max_age=refresh_max_age,
                               secret_key=secret_key,
                               private_key=private_key,
                               public_key=public_key,
                               request_timeout=request_timeout,
                               local_provider=local_provider,
                               logger=logger)


def jwt_remove_service_access(service_url: str,
                              logger: Logger = None) -> None:
    """
    Remove from storage the JWT access data for *service_url*.

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
        token_data: dict[str, Any] = __jwt_data.get_token_data(service_url=service_url,
                                                               logger=logger)
        result = token_data.get("access_token")
    except Exception as e:
        if logger:
            logger.error(msg=str(e))
        errors.append(str(e))

    return result


def jwt_get_token_data(errors: list[str],
                       service_url: str,
                       logger: Logger = None) -> dict[str, Any]:
    """
    Obtain and return the JWT token associated with *service_url*, along with its duration.

    Structure of the return data:
    {
      "access_token": <jwt-token>,
      "expires_in": <seconds-to-expiration>
    }

    :param errors: incidental error messages
    :param service_url: the reference URL for obtaining JWT tokens
    :param logger: optional logger
    :return: the JWT token data, or 'None' if error
    """
    # inicialize the return variable
    result: dict[str, Any] | None = None

    try:
        result = __jwt_data.get_token_data(service_url=service_url,
                                           logger=logger)
    except Exception as e:
        if logger:
            logger.error(msg=str(e))
        errors.append(str(e))

    return result


def jwt_get_claims(errors: list[str],
                   token: str,
                   logger: Logger = None) -> dict[str, Any]:
    """
    Obtain and return the claimset of a JWT *token*.

    :param errors: incidental error messages
    :param token: the token to be inspected for claims
    :param logger: optional logger
    :return: the token's claimset, or 'None' if error
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    try:
        result = __jwt_data.get_token_claims(token=token)
    except Exception as e:
        if logger:
            logger.error(msg=str(e))
        errors.append(str(e))

    return result


def jwt_verify_request(request: Request,
                       logger: Logger = None) -> Response:
    """
    Verify wheher the HTTP *request* has the proper authorization, as per the JWT standard.

    :param request: the request to be verified
    :param logger: optional logger
    :return: 'None' if the request is valid, otherwise a 'Response' object reporting the error
    """
    # initialize the return variable
    result: Response | None = None

    # retrieve the authorization from the request header
    auth_header: str = request.headers.get("Authorization")

    # was a 'Bearer' authorization obtained ?
    if auth_header and auth_header.startswith("Bearer "):
        # yes, extract and validate the JWT token
        token: str = auth_header.split(" ")[1]
        try:
            jwt_validate_token(token=token,
                               key=JWT_HS_SECRET_KEY or JWT_RSA_PUBLIC_KEY,
                               algorithm=JWT_DEFAULT_ALGORITHM)
        except Exception as e:
            # validation failed
            if logger:
                logger.error(msg=str(e))
            result = Response(response=str(e),
                              status=401)
    else:
        # no, report the error
        result = Response(response="Authorization failed",
                          status=401)

    return result


# @flask_app.route(rule="/jwt-service",
#                  methods=["POST"])
def jwt_service(service_url: str = None) -> Response:
    """
    Entry point for obtaining JWT tokens.

    In order to be serviced, the invoker must send, in the body of the request,
    a JSON containing:
    {
      "service-url": "<url>",                               - the JWT reference URL (if not as parameter)
      "<custom-claim-key-1>": "<custom-claim-value-1>",     - the registered custom claims
      ...
      "<custom-claim-key-n>": "<custom-claim-value-n>"
    }

    Structure of the return data:
    {
      "access_token": <jwt-token>,
      "expires_in": <seconds-to-expiration>
    }

    :param service_url: the JWT reference URL, alternatively passed in the body's JSON
    :return: the requested JWT token, along with its duration.
    """
    # declare the return variable
    result: Response

    # obtain the parameters
    # noinspection PyUnusedLocal
    params: dict[str, Any] = {}
    with contextlib.suppress(Exception):
        params = request.get_json()

    # validate the parameters
    valid: bool = False
    if not service_url:
        service_url = params.get("service-url")
    if service_url:
        item_data: dict[str, dict[str, Any]] = __jwt_data.retrieve_access_data(service_url=service_url)
        if item_data:
            valid = True
            custom_claims: dict[str, Any] = item_data.get("custom-claims")
            for key, value in custom_claims.items():
                if key not in params or params.get(key) != value:
                    valid = False
                    break

    # obtain the token data
    if valid:
        try:
            token_data: dict[str, Any] = __jwt_data.get_token_data(service_url=service_url)
            result = jsonify(token_data)
        except Exception as e:
            result = Response(response=str(e),
                              status=401)
    else:
        result = Response(response="Invalid parameters",
                          status=401)

    return result
