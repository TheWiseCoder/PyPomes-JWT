import jwt
import sys
from base64 import b64decode
from flask import Request, Response, request
from logging import Logger
from pypomes_core import exc_format
from pypomes_db import (
    DbEngine, db_connect, db_commit,
    db_rollback, db_close, db_select, db_delete
)
from typing import Any

from .jwt_config import JwtConfig, JwtDbConfig
from .jwt_registry import JwtRegistry

# the JWT registry
__jwt_registry: JwtRegistry = JwtRegistry()


def jwt_needed(func: callable) -> callable:
    """
    Create a decorator to authenticate service endpoints with JWT tokens.

    :param func: the function being decorated
    """
    # ruff: noqa: ANN003 - Missing type annotation for *{name}
    def wrapper(*args, **kwargs) -> Response:
        response: Response = jwt_verify_request(request=request)
        return response if response else func(*args, **kwargs)

    # prevent a rogue error ("View function mapping is overwriting an existing endpoint function")
    wrapper.__name__ = func.__name__

    return wrapper


def jwt_verify_request(request: Request) -> Response:
    """
    Verify whether the HTTP *request* has the proper authorization, as per the JWT standard..

    This implementation assumes that HTTP requests are handled with the *Flask* framework.

    :param request: the *request* to be verified
    :return: *None* if the *request* is valid, otherwise a *Response* reporting the error
    """
    # initialize the return variable
    result: Response | None = None

    # retrieve the authorization from the request header
    auth_header: str = request.headers.get("Authorization")

    # validate the authorization token
    bad_token: bool = True
    if auth_header and auth_header.startswith("Bearer "):
        # yes, extract and validate the JWT access token
        token: str = auth_header.split(" ")[1]
        claims: dict[str, Any] = jwt_validate_token(token=token,
                                                    nature="A")
        if claims:
            login: str = request.values.get("login")
            subject: str = claims["payload"].get("sub")
            if not login or not subject or login == subject:
                bad_token = False

    # deny the authorization
    if bad_token:
        result = Response(response="Authorization failed",
                          status=401)
    return result


def jwt_assert_account(account_id: str) -> bool:
    """
    Determine whether access for *account_id* has been established.

    :param account_id: the account identification
    :return: *True* if access data exists for *account_id*, *False* otherwise
    """
    return __jwt_registry.access_registry.get(account_id) is not None


def jwt_set_account(account_id: str,
                    claims: dict[str, Any],
                    access_max_age: int = JwtConfig.ACCESS_MAX_AGE.value,
                    refresh_max_age: int = JwtConfig.REFRESH_MAX_AGE.value,
                    lead_interval: int = None,
                    logger: Logger = None) -> None:
    """
    Establish the data needed to obtain JWT tokens for *account_id*.

    The parameter *claims* may contain account-related claims, only. Ideally, it should contain,
    at a minimum, *iss*, *birthdate*, *email*, *gender*, *name*, and *roles*.
    It is enforced that the parameter *refresh_max_age* should be at least 300 seconds greater
    than *access-max-age*.

    :param account_id: the account identification
    :param claims: the JWT claimset, as key-value pairs
    :param access_max_age: access token duration, in seconds
    :param refresh_max_age: refresh token duration, in seconds
    :param lead_interval: optional time to wait for token to be valid, in seconds
    :param logger: optional logger
    """
    if logger:
        logger.debug(msg=f"Registering account data for '{account_id}'")

    # register the JWT service
    __jwt_registry.add_account(account_id=account_id,
                               claims=claims,
                               access_max_age=access_max_age,
                               refresh_max_age=max(refresh_max_age, access_max_age + 300),
                               lead_interval=lead_interval,
                               logger=logger)


def jwt_remove_account(account_id: str,
                       logger: Logger = None) -> bool:
    """
    Remove from storage the JWT access data for *account_id*.

    :param account_id: the account identification
    :param logger: optional logger
    return: *True* if the access data was removed, *False* otherwise
    """
    if logger:
        logger.debug(msg=f"Remove access data for '{account_id}'")

    return __jwt_registry.remove_account(account_id=account_id,
                                         logger=logger)


def jwt_validate_token(token: str,
                       nature: str = None,
                       account_id: str = None,
                       errors: list[str] = None,
                       logger: Logger = None) -> dict[str, Any] | None:
    """
    Verify if *token* is a valid JWT token.

    Attempt to validate non locally issued tokens will not succeed. If *nature* is provided,
    validate whether *token* is of that nature. A token issued locally has the header claim *kid*
    starting with *A* (for *Access*) or *R* (for *Refresh*), followed by its id in the token database,
    or as a single letter in the range *[B-Z]*, less *R*. If the *kid* claim contains such an id,
    then the cryptographic key needed for validation will be obtained from the token database.
    Otherwise, the current decoding key is used.

    On success, return the token's claims (*header* and *payload*), as documented in *jwt_get_claims()*
    On failure, *errors* will contain the reason(s) for rejecting *token*.

    :param token: the token to be validated
    :param nature: prefix identifying the nature of locally issued tokens
    :param account_id: optionally, validate the token's account owner
    :param errors: incidental error messages
    :param logger: optional logger
    :return: The token's claims (*header* and *payload*) if it is valid, *None* otherwise
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    if logger:
        logger.debug(msg="Validate JWT token")

    # make sure to have an errors list
    if not isinstance(errors, list):
        errors = []

    # extract needed data from token header
    token_header: dict[str, Any] | None = None
    try:
        token_header: dict[str, Any] = jwt.get_unverified_header(jwt=token)
    except Exception as e:
        exc_err: str = exc_format(exc=e,
                                  exc_info=sys.exc_info())
        if logger:
            logger.error(msg=f"Error retrieving the token's header: {exc_err}")
        errors.append(exc_err)

    if not errors:
        token_kid: str = token_header.get("kid")
        token_alg: str | None = None
        token_decoder: bytes | None = None

        # retrieve token data from database
        if nature and not (token_kid and token_kid[0:1] == nature):
            if logger:
                logger.error(f"Nature of token's 'kid' ('{token_kid}') not '{nature}'")
            errors.append("Invalid token")
        elif token_kid and len(token_kid) > 1 and \
                token_kid[0:1] in ["A", "R"] and token_kid[1:].isdigit():
            # token was likely issued locally
            where_data: dict[str, Any] = {JwtDbConfig.COL_KID: int(token_kid[1:])}
            if account_id:
                where_data[JwtDbConfig.COL_ACCOUNT] = account_id
            recs: list[tuple[str]] = db_select(sel_stmt=f"SELECT {JwtDbConfig.COL_ALGORITHM}, "
                                                        f"{JwtDbConfig.COL_DECODER} "
                                                        f"FROM {JwtDbConfig.TABLE}",
                                               where_data=where_data,
                                               engine=DbEngine(JwtDbConfig.ENGINE),
                                               errors=errors,
                                               logger=logger)
            if recs:
                token_alg = recs[0][0]
                token_decoder = b64decode(recs[0][1])
            elif errors:
                if logger:
                    logger.error(msg=f"Error retrieving the token's decoder: {'; '.join(errors)}")
            else:
                if logger:
                    logger.error(msg="Token not in the database")
                errors.append("Invalid token")
        else:
            token_alg = JwtConfig.DEFAULT_ALGORITHM.value
            token_decoder = JwtConfig.DECODING_KEY.value

        # validate the token
        if not errors:
            try:
                # raises:
                #   InvalidTokenError: token is invalid
                #   InvalidKeyError: authentication key is not in the proper format
                #   ExpiredSignatureError: token and refresh period have expired
                #   InvalidSignatureError: signature does not match the one provided as part of the token
                #   ImmatureSignatureError: 'nbf' or 'iat' claim represents a timestamp in the future
                #   InvalidAlgorithmError: the specified algorithm is not recognized
                #   InvalidIssuedAtError: 'iat' claim is non-numeric
                #   MissingRequiredClaimError: a required claim is not contained in the claimset
                payload: dict[str, Any] = jwt.decode(jwt=token,
                                                     options={
                                                         "verify_signature": True,
                                                         "verify_exp": True,
                                                         "verify_nbf": True
                                                     },
                                                     key=token_decoder,
                                                     require=["iat", "iss", "exp", "sub"],
                                                     algorithms=token_alg)
                if account_id and payload.get("sub") != account_id:
                    if logger:
                        logger.error(msg=f"Token does not belong to account '{account_id}'")
                    errors.append("Invalid token")
                else:
                    result = {
                        "header": token_header,
                        "payload": payload
                    }
            except Exception as e:
                exc_err: str = exc_format(exc=e,
                                          exc_info=sys.exc_info())
                if logger:
                    logger.error(msg=f"Error decoding the token: {exc_err}")
                errors.append(exc_err)

    if not errors and logger:
        logger.debug(msg="Token is valid")

    return result


def jwt_revoke_token(account_id: str,
                     token: str,
                     errors: list[str] = None,
                     logger: Logger = None) -> bool:
    """
    Revoke the *refresh_token* associated with *account_id*.

    Revoke operations require access to a database table defined by *JWT_DB_TABLE*.

    :param account_id: the account identification
    :param token: the token to be revoked
    :param errors: incidental error messages
    :param logger: optional logger
    :return: *True* if operation could be performed, *False* otherwise
    """
    # initialize the return variable
    result: bool = False

    if logger:
        logger.debug(msg=f"Revoking token of account '{account_id}'")

    # make sure to have an errors list
    if not isinstance(errors, list):
        errors = []

    token_claims: dict[str, Any] = jwt_validate_token(token=token,
                                                      account_id=account_id,
                                                      errors=errors,
                                                      logger=logger)
    if not errors:
        token_kid: str = token_claims["header"].get("kid")
        if token_kid[0:1] not in ["A", "R"]:
            errors.append("Invalid token")
        else:
            db_delete(delete_stmt=f"DELETE FROM {JwtDbConfig.TABLE}",
                      where_data={
                          JwtDbConfig.COL_KID: int(token_kid[1:]),
                          JwtDbConfig.COL_ACCOUNT: account_id
                      },
                      engine=DbEngine(JwtDbConfig.ENGINE),
                      errors=errors,
                      logger=logger)
    if not errors:
        result = True
    elif logger:
        logger.error(msg="; ".join(errors))

    return result


def jwt_issue_token(account_id: str,
                    nature: str,
                    duration: int,
                    lead_interval: int = None,
                    claims: dict[str, Any] = None,
                    errors: list[str] = None,
                    logger: Logger = None) -> str:
    """
    Issue or refresh, and return, a JWT token associated with *account_id*, of the specified *nature*.

    The parameter *nature* must be a single letter in the range *[B-Z]*, less *R*
    (*A* is reserved for *access* tokens, and *R* for *refresh* tokens).
    The parameter *duration* specifies the token's validity interval (at least 60 seconds).
    These claims are ignored, if specified in *claims*: *iat*, *iss*, *exp*, *jti*, *nbf*, and *sub*.

    :param account_id: the account identification
    :param nature: the token's nature, must be a single letter in the range *[B-Z]*, less *R*
    :param duration: the number of seconds for the token to remain valid (at least 60 seconds)
    :param claims: optional token's claims
    :param lead_interval: optional interval for the token to become active (in seconds)
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the JWT token data, or *None* if error
    """
    # inicialize the return variable
    result: str | None = None

    if logger:
        logger.debug(msg=f"Issuing a JWT token for '{account_id}'")

    try:
        result = __jwt_registry.issue_token(account_id=account_id,
                                            nature=nature,
                                            duration=duration,
                                            claims=claims,
                                            lead_interval=lead_interval,
                                            logger=logger)
        if logger:
            logger.debug(msg=f"Token is '{result}'")
    except Exception as e:
        # token issuing failed
        exc_err: str = exc_format(exc=e,
                                  exc_info=sys.exc_info())
        if logger:
            logger.error(msg=f"Error issuing the token: {exc_err}")
        if isinstance(errors, list):
            errors.append(exc_err)

    return result


def jwt_issue_tokens(account_id: str,
                     account_claims: dict[str, Any] = None,
                     errors: list[str] = None,
                     logger: Logger = None) -> dict[str, Any]:
    """
    Issue the JWT token pair associated with *account_id*, for access and refresh operations.

    These claims are ignored, if provided in *account_claims*: *iat*, *iss*, *exp*, *jti*, *nbf*, and *sub*.
    Other claims specified therein may supercede currently registered account-related claims.

    Structure of the return data:
    {
      "access-token": <jwt-token>,
      "created-in": <timestamp>,
      "expires-in": <seconds-to-expiration>,
      "refresh-token": <jwt-token>
    }

    :param account_id: the account identification
    :param account_claims: if provided, may supercede currently registered account-related claims
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the JWT token data, or *None* if error
    """
    # inicialize the return variable
    result: dict[str, Any] | None = None

    if logger:
        logger.debug(msg=f"Issuing a JWT token pair for '{account_id}'")

    try:
        result = __jwt_registry.issue_tokens(account_id=account_id,
                                             account_claims=account_claims,
                                             logger=logger)
        if logger:
            logger.debug(msg=f"Token data is '{result}'")
    except Exception as e:
        # token issuing failed
        exc_err: str = exc_format(exc=e,
                                  exc_info=sys.exc_info())
        if logger:
            logger.error(msg=f"Error issuing the token pair: {exc_err}")
        if isinstance(errors, list):
            errors.append(exc_err)

    return result


def jwt_refresh_tokens(account_id: str,
                       refresh_token: str,
                       errors: list[str] = None,
                       logger: Logger = None) -> dict[str, Any]:
    """
    Refresh the JWT token pair associated with *account_id*, for access and refresh operations.

    The claims in *refresh-token* are used on issuing the new tokens.

    Structure of the return data:
    {
      "access-token": <jwt-token>,
      "created-in": <timestamp>,
      "expires-in": <seconds-to-expiration>,
      "refresh-token": <jwt-token>
    }

    :param errors: incidental error messages
    :param account_id: the account identification
    :param refresh_token: the base refresh token
    :param logger: optional logger
    :return: the JWT token data, or *None* if error
    """
    # inicialize the return variable
    result: dict[str, Any] | None = None

    if logger:
        logger.debug(msg=f"Refreshing a JWT token pair for '{account_id}'")

    # make sure to have an errors list
    if not isinstance(errors, list):
        errors = []

    # assert the refresh token
    if refresh_token:
        # is the refresh token valid ?
        token_claims: dict[str, Any] = jwt_validate_token(token=refresh_token,
                                                          nature="R",
                                                          account_id=account_id,
                                                          errors=errors,
                                                          logger=logger)
        if token_claims:
            # yes, proceed
            token_kid: str = token_claims["header"].get("kid")

            # start the database transaction
            db_conn: Any = db_connect(autocommit=False,
                                      engine=DbEngine(JwtDbConfig.ENGINE),
                                      errors=errors,
                                      logger=logger)
            if db_conn:
                # delete current refresh token
                db_delete(delete_stmt=f"DELETE FROM {JwtDbConfig.TABLE}",
                          where_data={
                              JwtDbConfig.COL_KID: int(token_kid[1:]),
                              JwtDbConfig.COL_ACCOUNT: account_id
                          },
                          engine=DbEngine(JwtDbConfig.ENGINE),
                          connection=db_conn,
                          committable=False,
                          errors=errors,
                          logger=logger)

                # issue the token pair
                if not errors:
                    try:
                        result = __jwt_registry.issue_tokens(account_id=account_id,
                                                             account_claims=token_claims.get("payload"),
                                                             db_conn=db_conn,
                                                             logger=logger)
                        if logger:
                            logger.debug(msg=f"Token pair was refreshed for account '{account_id}'")
                    except Exception as e:
                        # token issuing failed
                        exc_err: str = exc_format(exc=e,
                                                  exc_info=sys.exc_info())
                        if logger:
                            logger.error(msg=f"Error refreshing the token pair: {exc_err}")
                        errors.append(exc_err)

                # wrap-up the transaction
                if errors:
                    db_rollback(connection=db_conn,
                                logger=logger)
                else:
                    db_commit(connection=db_conn,
                              errors=errors,
                              logger=logger)
                db_close(connection=db_conn,
                         logger=logger)
    else:
        # refresh token not found
        errors.append("Refresh token was not provided")

    if errors and logger:
        logger.error(msg="; ".join(errors))

    return result


def jwt_get_claims(token: str,
                   errors: list[str] = None,
                   logger: Logger = None) -> dict[str, Any] | None:
    """
    Retrieve the claims set of a JWT *token*.

    Any well-constructed JWT token may be provided in *token*, as this operation is not restricted
    to locally issued tokens. Note that neither the token's signature nor its expiration is verified.

    Structure of the returned data, for locally issued tokens:
      {
        "header": {
          "alg": "RS256",
          "typ": "JWT",
          "kid": "A1234"
        },
        "payload": {
          "valid-from": <YYYY-MM-DDThh:mm:ss+00:00>
          "valid-until": <YYYY-MM-DDThh:mm:ss+00:00>
          "birthdate": "1980-01-01",
          "email": "jdoe@mail.com",
          "exp": 1516640454,
          "iat": 1516239022,
          "iss": "my_jwt_provider.com",
          "jti": "Uhsdfgr67FGH567qwSDF33er89retert",
          "gender": "M",
          "name": "John Doe",
          "nbt": 1516249022
          "sub": "11111111111",
          "roles": [
            "administrator",
            "operator"
          ]
        }
      }

    :param token: the token to be inspected for claims
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the token's claimset, or *None* if error
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    if logger:
        logger.debug(msg="Retrieve claims for token")

    try:
        header: dict[str, Any] = jwt.get_unverified_header(jwt=token)
        payload: dict[str, Any] = jwt.decode(jwt=token,
                                             options={"verify_signature": False})
        result = {
            "header": header,
            "payload": payload
        }
    except Exception as e:
        exc_err: str = exc_format(exc=e,
                                  exc_info=sys.exc_info())
        if logger:
            logger.error(msg=f"Error retrieving the token's claimsn: {exc_err}")
        if isinstance(errors, list):
            errors.append(exc_err)

    return result
