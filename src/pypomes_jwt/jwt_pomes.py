import contextlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from datetime import datetime
from flask import Request, Response, request, jsonify
from logging import Logger
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
                                                def_value=token_bytes(nbytes=32))
# the endpoint must invoke 'jwt_service()' below
JWT_ENDPOINT_URL: Final[str] = env_get_str(key=f"{APP_PREFIX}_JWT_ENDPOINT_URL")

# obtain a RSA private/public key pair
__priv_bytes: bytes = env_get_bytes(key=f"{APP_PREFIX}_JWT_RSA_PRIVATE_KEY")
__pub_bytes: bytes = env_get_bytes(key=f"{APP_PREFIX}_JWT_RSA_PUBLIC_KEY")
if not __priv_bytes or not __pub_bytes:
    __priv_key: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537,
                                                         key_size=2048)
    __priv_bytes = __priv_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption())
    __pub_key: RSAPublicKey = __priv_key.public_key()
    __pub_bytes = __pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
JWT_RSA_PRIVATE_KEY: Final[bytes] = __priv_bytes
JWT_RSA_PUBLIC_KEY: Final[bytes] = __pub_bytes

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


def jwt_assert_access(account_id: str) -> bool:
    """
    Determine whether access for *ccount_id* has been established.

    :param account_id: the account identification
    :return: *True* if access data exists for *account_id*, *False* otherwise
    """
    return __jwt_data.get_access_data(account_id=account_id) is not None


def jwt_set_access(account_id: str,
                   reference_url: str,
                   claims: dict[str, Any],
                   algorithm: Literal["HS256", "HS512", "RSA256", "RSA512"] = JWT_DEFAULT_ALGORITHM,
                   access_max_age: int = JWT_ACCESS_MAX_AGE,
                   refresh_max_age: int = JWT_REFRESH_MAX_AGE,
                   secret_key: bytes = JWT_HS_SECRET_KEY,
                   private_key: bytes = JWT_RSA_PRIVATE_KEY,
                   public_key: bytes = JWT_RSA_PUBLIC_KEY,
                   request_timeout: int = None,
                   remote_provider: bool = True,
                   logger: Logger = None) -> None:
    """
    Set the data needed to obtain JWT tokens for *account_id*.

    :param account_id: the account identification
    :param reference_url: the reference URL (for remote providers, URL to obtain and validate the JWT tokens)
    :param claims: the JWT claimset, as key-value pairs
    :param algorithm: the authentication type
    :param access_max_age: token duration, in seconds
    :param refresh_max_age: duration for the refresh operation, in seconds
    :param secret_key: secret key for HS authentication
    :param private_key: private key for RSA authentication
    :param public_key: public key for RSA authentication
    :param request_timeout: timeout for the requests to the reference URL
    :param remote_provider: whether the JWT provider is a remote server
    :param logger: optional logger
    """
    if logger:
        logger.debug(msg=f"Register access data for '{account_id}'")

    # extract the claims provided in the reference URL's query string
    pos: int = reference_url.find("?")
    if pos > 0:
        params: list[str] = reference_url[pos+1:].split(sep="&")
        for param in params:
            claims[param.split("=")[0]] = param.split("=")[1]
        reference_url = reference_url[:pos]

    # register the JWT service
    __jwt_data.add_access_data(account_id=account_id,
                               reference_url=reference_url,
                               claims=claims,
                               algorithm=algorithm,
                               access_max_age=access_max_age,
                               refresh_max_age=refresh_max_age,
                               hs_secret_key=secret_key,
                               rsa_private_key=private_key,
                               rsa_public_key=public_key,
                               request_timeout=request_timeout,
                               remote_provider=remote_provider,
                               logger=logger)


def jwt_remove_access(account_id: str,
                      logger: Logger = None) -> None:
    """
    Remove from storage the JWT access data for *account_id*.

    :param account_id: the account identification
    :param logger: optional logger
    """
    if logger:
        logger.debug(msg=f"Remove access data for '{account_id}'")

    __jwt_data.remove_access_data(account_id=account_id,
                                  logger=logger)


def jwt_get_token(errors: list[str],
                  account_id: str,
                  logger: Logger = None) -> str:
    """
    Obtain and return a JWT token for *account_id*.

    :param errors: incidental error messages
    :param account_id: the account identification
    :param logger: optional logger
    :return: the JWT token, or *None* if an error ocurred
    """
    # inicialize the return variable
    result: str | None = None

    if logger:
        logger.debug(msg=f"Obtain a JWT token for '{account_id}'")

    try:
        token_data: dict[str, Any] = __jwt_data.get_token_data(account_id=account_id,
                                                               logger=logger)
        result = token_data.get("access_token")
        if logger:
            logger.debug(f"Token is '{result}'")
    except Exception as e:
        if logger:
            logger.error(msg=str(e))
        errors.append(str(e))

    return result


def jwt_get_token_data(errors: list[str],
                       account_id: str,
                       logger: Logger = None) -> dict[str, Any]:
    """
    Obtain and return the JWT token associated with *account_id*, along with its duration.

    Structure of the return data:
    {
      "access_token": <jwt-token>,
      "created_in": <timestamp>,
      "expires_in": <seconds-to-expiration>
    }

    :param errors: incidental error messages
    :param account_id: the account identification
    :param logger: optional logger
    :return: the JWT token data, or *None* if error
    """
    # inicialize the return variable
    result: dict[str, Any] | None = None

    if logger:
        logger.debug(msg=f"Retrieve JWT token data for '{account_id}'")
    try:
        result = __jwt_data.get_token_data(account_id=account_id,
                                           logger=logger)
        if logger:
            logger.debug(msg=f"Data is '{result}'")
    except Exception as e:
        if logger:
            logger.error(msg=str(e))
        errors.append(str(e))

    return result


def jwt_get_token_claims(errors: list[str],
                         token: str,
                         logger: Logger = None) -> dict[str, Any]:
    """
    Obtain and return the claims set of a JWT *token*.

    :param errors: incidental error messages
    :param token: the token to be inspected for claims
    :param logger: optional logger
    :return: the token's claimset, or 'None' if error
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    if logger:
        logger.debug(msg=f"Retrieve claims for token '{token}'")

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
    :return: *None* if the request is valid, otherwise a *Response* object reporting the error
    """
    # initialize the return variable
    result: Response | None = None

    if logger:
        logger.debug(msg="Validate a JWT token")
    err_msg: str | None = None

    # retrieve the authorization from the request header
    auth_header: str = request.headers.get("Authorization")

    # was a 'Bearer' authorization obtained ?
    if auth_header and auth_header.startswith("Bearer "):
        # yes, extract and validate the JWT token
        token: str = auth_header.split(" ")[1]
        if logger:
            logger.debug(msg=f"Token is '{token}'")
        # retrieve the reference access data
        access_data: dict[str, Any] = __jwt_data.get_access_data(access_token=token)
        if access_data:
            control_data: dict[str, Any] = access_data.get("control-data")
            if control_data.get("remote-provider"):
                # JWT provider is remote
                if datetime.now().timestamp() > access_data.get("reserved-claims").get("exp"):
                    err_msg = "Token has expired"
            else:
                # JWT was locally provided
                try:
                    jwt_validate_token(token=token,
                                       key=(control_data.get("hs-secret-key") or
                                            control_data.get("rsa-public-key")),
                                       algorithm=control_data.get("algorithm"))
                except Exception as e:
                    # validation failed
                    err_msg = str(e)
        else:
            err_msg = "No access data found for token"
    else:
        # no 'Bearer' found, report the error
        err_msg = "Request header has no 'Bearer' data"

    # log the error and deny the authorization
    if err_msg:
        if logger:
            logger.error(msg=err_msg)
        result = Response(response="Authorization failed",
                          status=401)

    return result


def jwt_service(account_id: str = None,
                service_params: dict[str, Any] = None,
                logger: Logger = None) -> Response:
    """
    Entry point for obtaining JWT tokens.

    In order to be serviced, the invoker must send, as parameter *service_params* or in the body of the request:
    {
      "account-id": "<string>"                              - required account identification
      "<custom-claim-key-1>": "<custom-claim-value-1>",     - optional custom claims
      ...
      "<custom-claim-key-n>": "<custom-claim-value-n>"
    }
    If provided, the additional custom claims will be sent to the remote provider, if applicable
    (custom claims currently registered for the account may be overridden).


    Structure of the return data:
    {
      "access_token": <jwt-token>,
      "created_in": <timestamp>,
      "expires_in": <seconds-to-expiration>
    }

    :param account_id: the account identification, alternatively passed in JSON
    :param service_params: the optional JSON containing the request parameters (defaults to JSON in body)
    :param logger: optional logger
    :return: a *Response* containing the requested JWT token and its duration, or reporting an error
    """
    # declare the return variable
    result: Response

    if logger:
        msg: str = "Service a JWT request"
        if request:
            msg += f" from '{request.base_url}'"
        logger.debug(msg=msg)

    # retrieve the parameters
    # noinspection PyUnusedLocal
    params: dict[str, Any] = service_params or {}
    if not params:
        with contextlib.suppress(Exception):
            params = request.get_json()
    if not account_id:
        account_id = params.get("account-id")

    # has the account been identified ?
    if account_id:
        # yes, proceed
        if logger:
            logger.debug(msg=f"Account identification is '{account_id}'")
        item_data: dict[str, dict[str, Any]] = __jwt_data.get_access_data(account_id=account_id,
                                                                          logger=logger) or {}
        custom_claims: dict[str, Any] = item_data.get("custom-claims").copy()
        for key, value in params.items():
            custom_claims[key] = value

        # obtain the token data
        try:
            token_data: dict[str, Any] = __jwt_data.get_token_data(account_id=account_id,
                                                                   logger=logger)
            result = jsonify(token_data)
        except Exception as e:
            # token validation failed
            if logger:
                logger.error(msg=str(e))
            result = Response(response=str(e),
                              status=401)
    else:
        # no, report the problem
        if logger:
            logger.debug(msg=f"Invalid parameters {service_params}")
        result = Response(response="Invalid parameters",
                          status=401)

    return result
