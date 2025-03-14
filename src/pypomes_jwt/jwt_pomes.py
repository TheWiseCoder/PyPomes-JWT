import jwt
from base64 import urlsafe_b64decode
from flask import Request, Response, request
from logging import Logger
from pypomes_db import db_select, db_delete
from typing import Any

from . import JWT_DB_COL_ACCOUNT
from .jwt_constants import (
    JWT_ACCESS_MAX_AGE, JWT_REFRESH_MAX_AGE,
    JWT_DEFAULT_ALGORITHM, JWT_DECODING_KEY,
    JWT_DB_TABLE, JWT_DB_COL_KID, JWT_DB_COL_ALGORITHM, JWT_DB_COL_DECODER
)
from .jwt_data import JwtData

# the JWT data object
__jwt_data: JwtData = JwtData()


def jwt_needed(func: callable) -> callable:
    """
    Create a decorator to authenticate service endpoints with JWT tokens.

    :param func: the function being decorated
    """
    # ruff: noqa: ANN003
    def wrapper(*args, **kwargs) -> Response:
        response: Response = jwt_verify_request(request=request)
        return response if response else func(*args, **kwargs)

    # prevent a rogue error ("View function mapping is overwriting an existing endpoint function")
    wrapper.__name__ = func.__name__

    return wrapper


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
        # yes, extract and validate the JWT access token
        token: str = auth_header.split(" ")[1]
        if logger:
            logger.debug(msg="Token was found")
        errors: list[str] = []
        jwt_validate_token(errors=errors,
                           nature=["A"],
                           token=token)
        if errors:
            err_msg = "; ".join(errors)
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


def jwt_assert_account(account_id: str) -> bool:
    """
    Determine whether access for *account_id* has been established.

    :param account_id: the account identification
    :return: *True* if access data exists for *account_id*, *False* otherwise
    """
    return __jwt_data.access_data.get(account_id) is not None


def jwt_set_account(account_id: str,
                    reference_url: str,
                    claims: dict[str, Any],
                    access_max_age: int = JWT_ACCESS_MAX_AGE,
                    refresh_max_age: int = JWT_REFRESH_MAX_AGE,
                    grace_interval: int = None,
                    token_audience: str = None,
                    token_nonce: str = None,
                    request_timeout: int = None,
                    remote_provider: bool = True,
                    logger: Logger = None) -> None:
    """
    Set the data needed to obtain JWT tokens for *account_id*.

    :param account_id: the account identification
    :param reference_url: the reference URL (for remote providers, URL to obtain and validate the JWT tokens)
    :param claims: the JWT claimset, as key-value pairs
    :param access_max_age: access token duration, in seconds
    :param refresh_max_age: refresh token duration, in seconds
    :param grace_interval: optional time to wait for token to be valid, in seconds
    :param token_audience: optional audience the token is intended for
    :param token_nonce: optional value used to associate a client session with a token
    :param request_timeout: timeout for the requests to the reference URL
    :param remote_provider: whether the JWT provider is a remote server
    :param logger: optional logger
    """
    if logger:
        logger.debug(msg=f"Register account data for '{account_id}'")

    # extract the claims provided in the reference URL's query string
    pos: int = reference_url.find("?")
    if pos > 0:
        params: list[str] = reference_url[pos+1:].split(sep="&")
        for param in params:
            claims[param.split("=")[0]] = param.split("=")[1]
        reference_url = reference_url[:pos]

    # register the JWT service
    __jwt_data.add_account(account_id=account_id,
                           reference_url=reference_url,
                           claims=claims,
                           access_max_age=access_max_age,
                           refresh_max_age=refresh_max_age,
                           grace_interval=grace_interval,
                           token_audience=token_audience,
                           token_nonce=token_nonce,
                           request_timeout=request_timeout,
                           remote_provider=remote_provider,
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

    return __jwt_data.remove_account(account_id=account_id,
                                     logger=logger)


def jwt_validate_token(errors: list[str] | None,
                       token: str,
                       nature: list[str] = None,
                       account_id: str = None,
                       logger: Logger = None) -> dict[str, Any] | None:
    """
    Verify if *token* ia a valid JWT token.

    Raise an appropriate exception if validation failed.
    if *nature* is provided, it is checked whether *token* has been locally issued and is of a appropriate nature.
    A token issued locally has the header claim *kid* starting with "A" (for *Access*) or "R" (for *Refresh*),
    followed by its id in the token database.

    :param errors: incidental error messages
    :param token: the token to be validated
    :param nature: one of more prefixes identifying the nature of locally issued tokens
    :param account_id: optionally, validate the token's account owner
    :param logger: optional logger
    :return: The token's claims (header and payload) if if is valid, *None* otherwise
    """
    # initialize the return variable
    result: dict[str, Any] | None = None
    if logger:
        logger.debug(msg="Validate JWT token")

    # extract needed data from token header
    token_header: dict[str, Any] = jwt.get_unverified_header(jwt=token)
    token_kid: str = token_header.get("kid")
    token_alg: str | None = None
    token_decoder: bytes | None = None
    op_errors: list[str] = []

    # retrieve token data from database
    if nature and not (token_kid and token_kid[0:1] in nature):
        op_errors.append("Invalid token")
    elif token_kid:
        where_data: dict[str, Any] = {JWT_DB_COL_KID: int(token_kid[1:])}
        if account_id:
            where_data[JWT_DB_COL_ACCOUNT] = account_id
        recs: list[tuple[str]] = db_select(errors=op_errors,
                                           sel_stmt=f"SELECT {JWT_DB_COL_ALGORITHM}, {JWT_DB_COL_DECODER} "
                                                    f"FROM {JWT_DB_TABLE}",
                                           where_data=where_data,
                                           logger=logger)
        if recs:
            token_alg = recs[0][0]
            token_decoder = urlsafe_b64decode(recs[0][1])
        else:
            op_errors.append("Invalid token")
    else:
        token_alg = JWT_DEFAULT_ALGORITHM
        token_decoder = JWT_DECODING_KEY

        # validate the token
    if not op_errors:
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
                op_errors.append("Token does not belong to account")
            else:
                result = {
                    "header": token_header,
                    "payload": payload
                }
        except Exception as e:
            op_errors.append(str(e))

    if op_errors:
        err_msg: str = "; ".join(op_errors)
        if logger:
            logger.error(msg=err_msg)
        if isinstance(errors, list):
            errors.extend(op_errors)
    elif logger:
        logger.debug(msg="Token is valid")

    return result


def jwt_revoke_token(errors: list[str] | None,
                     account_id: str,
                     refresh_token: str,
                     logger: Logger = None) -> bool:
    """
    Revoke the *refresh_token* associated with *account_id*.

    Revoke operations require access to a database table defined by *JWT_DB_TABLE*.

    :param errors: incidental error messages
    :param account_id: the account identification
    :param refresh_token: the token to be revolked
    :param logger: optional logger
    :return: *True* if operation could be performed, *False* otherwise
    """
    # initialize the return variable
    result: bool = False

    if logger:
        logger.debug(msg=f"Revoking refresh token of '{account_id}'")

    op_errors: list[str] = []
    token_claims: dict[str, Any] = jwt_validate_token(errors=op_errors,
                                                      token=refresh_token,
                                                      nature=["A", "R"],
                                                      account_id=account_id,
                                                      logger=logger)
    if not op_errors:
        token_kid: str = token_claims["header"].get("kid")
        db_delete(errors=op_errors,
                  delete_stmt=f"DELETE FROM {JWT_DB_TABLE}",
                  where_data={
                      JWT_DB_COL_KID: int(token_kid[1:]),
                      JWT_DB_COL_ACCOUNT: account_id
                  },
                  logger=logger)
    if op_errors:
        if logger:
            logger.error(msg="; ".join(op_errors))
        if isinstance(errors, list):
            errors.extend(op_errors)
    else:
        result = True

    return result


def jwt_get_tokens(errors: list[str] | None,
                   account_id: str,
                   account_claims: dict[str, Any] = None,
                   refresh_token: str = None,
                   logger: Logger = None) -> dict[str, Any]:
    """
    Issue or refresh, and return, the JWT token data associated with *account_id*.

    If *refresh_token* is provided, its claims are used on issuing the new tokens,
    and claims in *account_claims*, if any, are ignored.

    Structure of the return data:
    {
      "access_token": <jwt-token>,
      "created_in": <timestamp>,
      "expires_in": <seconds-to-expiration>,
      "refresh_token": <jwt-token>
    }

    :param errors: incidental error messages
    :param account_id: the account identification
    :param account_claims: if provided, may supercede registered claims
    :param refresh_token: if provided, defines a token refresh operation
    :param logger: optional logger
    :return: the JWT token data, or *None* if error
    """
    # inicialize the return variable
    result: dict[str, Any] | None = None

    if logger:
        logger.debug(msg=f"Retrieve JWT token data for '{account_id}'")
    op_errors: list[str] = []
    if refresh_token:
        # verify whether this refresh token is legitimate
        account_claims = (jwt_validate_token(errors=op_errors,
                                             token=refresh_token,
                                             nature=["R"],
                                             account_id=account_id,
                                             logger=logger) or {}).get("payload")
        if account_claims:
            account_claims.pop("iat", None)
            account_claims.pop("jti", None)
            account_claims.pop("iss", None)
            account_claims.pop("exp", None)
            account_claims.pop("nbt", None)
    if not op_errors:
        try:
            result = __jwt_data.issue_tokens(account_id=account_id,
                                             account_claims=account_claims,
                                             logger=logger)
            if logger:
                logger.debug(msg=f"Token data is '{result}'")
        except Exception as e:
            # token issuing failed
            op_errors.append(str(e))

    if op_errors:
        if logger:
            logger.error("; ".join(op_errors))
        if isinstance(errors, list):
            errors.extend(op_errors)

    return result


def jwt_get_claims(errors: list[str] | None,
                   token: str,
                   validate: bool = False,
                   logger: Logger = None) -> dict[str, Any] | None:
    """
    Obtain and return the claims set of a JWT *token*.

    If *validate* is set to *True*, tha following pieces of information are verified:
      - the token was issued and signed by the local provider, and is not corrupted
      - the claim 'exp' is present and is in the future
      - the claim 'nbf' is present and is in the past

    Structure of the returned data:
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
          "iss": "https://my_id_provider/issue",
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

    :param errors: incidental error messages
    :param token: the token to be inspected for claims
    :param validate: If *True*, verifies the token's data (defaults to *False*)
    :param logger: optional logger
    :return: the token's claimset, or *None* if error
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    if logger:
        logger.debug(msg="Retrieve claims for token")

    try:
        # retrieve the token's claims
        if validate:
            result = jwt_validate_token(errors=errors,
                                        token=token,
                                        logger=logger)
        else:
            header: dict[str, Any] = jwt.get_unverified_header(jwt=token)
            payload: dict[str, Any] = jwt.decode(jwt=token,
                                                 options={"verify_signature": False})
            result = {
                "header": header,
                "payload": payload
            }
    except Exception as e:
        if logger:
            logger.error(msg=str(e))
        if isinstance(errors, list):
            errors.append(str(e))

    return result
