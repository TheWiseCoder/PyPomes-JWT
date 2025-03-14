import jwt
import requests
import string
import sys
from datetime import datetime, timezone
from logging import Logger
from pypomes_core import str_random
from pypomes_db import db_connect, db_commit, db_update, db_delete
from requests import Response
from threading import Lock
from typing import Any

from .jwt_constants import (
    JWT_DEFAULT_ALGORITHM, JWT_ACCOUNT_LIMIT, JWT_ENCODING_KEY, JWT_DECODING_KEY,
    JWT_DB_TABLE, JWT_DB_COL_KID, JWT_DB_COL_ACCOUNT,
    JWT_DB_COL_ALGORITHM, JWT_DB_COL_DECODER, JWT_DB_COL_TOKEN
)


class JwtData:
    """
    Shared JWT data for security token access.

    Instance variables:
      - access_lock: lock for safe multi-threading access
      - access_data: dictionary holding the JWT token data, organized by account id:
       {
         <account-id>: {
           "reference-url":              # the reference URL
           "remote-provider": <bool>,    # whether the JWT provider is a remote server
           "request-timeout": <int>,     # in seconds - defaults to no timeout
           "access-max-age": <int>,      # in seconds - defaults to JWT_ACCESS_MAX_AGE
           "refresh-max-age": <int>,     # in seconds - defaults to JWT_REFRESH_MAX_AGE
           "grace-interval": <int>       # time to wait for token to be valid, in seconds
           "token-audience": <string>    # the audience the token is intended for
           "token_nonce": <string>       # value used to associate a client session with a token
           "claims": {
             "valid-from": <string>      # token's start (<YYYY-MM-DDThh:mm:ss+00:00>)
             "valid-until": <string>     # token's finish (<YYYY-MM-DDThh:mm:ss+00:00>)
             "birthdate": <string>,      # subject's birth date
             "email": <string>,          # subject's email
             "gender": <string>,         # subject's gender
             "name": <string>,           # subject's name
             "roles": <List[str]>,       # subject roles
             "nonce": <string>,          # value used to associate a Client session with a token
             ...
           }
         },
         ...
       }

    JSON Web Token (JWT) is a compact, URL-safe means of representing claims to be transferred between
    two parties. It is fully described in the RFC 7519, issued by the Internet Engineering Task Force
    (see https://www.rfc-editor.org/rfc/rfc7519.html).
    In this context, claims are pieces of information a token bears, and herein are loosely classified
    as token-related and account-related. All times are UTC.

    Token-related claims are mostly required claims, and convey information about the token itself:
      "exp": <timestamp>        # expiration time
      "iat": <timestamp>        # issued at
      "iss": <string>           # issuer (for remote providers, URL to obtain and validate the access tokens)
      "jti": <string>           # JWT id
      "sub": <string>           # subject (the account identification)
      "nat": <string>           # nature of token (A: access; R: refresh) - locally issued tokens, only
      # optional:
      "aud": <string>           # token audience
      "nbt": <timestamp>        # not before time

    Account-related claims are optional claims, and convey information about the registered account they belong to.
    Alhough they can be freely specified, these are some of the most commonly used claims:
       "valid-from": <string>   # token's start (<YYYY-MM-DDThh:mm:ss+00:00>)
       "valid-until": <string>  # token's finish (<YYYY-MM-DDThh:mm:ss+00.00>)
      "birthdate": <string>     # subject's birth date
      "email": <string>         # subject's email
      "gender": <string>        # subject's gender
      "name": <string>          # subject's name
      "roles": <List[str]>      # subject roles
      "nonce": <string>         # value used to associate a client session with a token

    The token header has these items:
      "alg": <string>           # the algorithm used to sign the token (one of 'HS256', 'HS512', 'RSA256', 'RSA512')
      "typ": <string>           # the token type (fixed to 'JWT'
      "kid": <string>           # a reference to the encoding/decoding keys used
                                # (if issued by the local server, holds the public key, if assimetric keys were used)
    """
    def __init__(self) -> None:
        """
        Initizalize the token access data.
        """
        self.access_lock: Lock = Lock()
        self.access_data: dict[str, Any] = {}

    def add_account(self,
                    account_id: str,
                    reference_url: str,
                    claims: dict[str, Any],
                    access_max_age: int,
                    refresh_max_age: int,
                    grace_interval: int,
                    token_audience: str,
                    token_nonce: str,
                    request_timeout: int,
                    remote_provider: bool,
                    logger: Logger = None) -> None:
        """
        Add to storage the parameters needed to produce and validate JWT tokens for *account_id*.

        The parameter *claims* may contain account-related claims, only. Ideally, it should contain,
        at a minimum, "birthdate", "email", "gender", "name", and "roles".
        If the token provider is local, then the token-related claims are created at token issuing time.
        If the token provider is remote, all claims are sent to it at token request time.

        :param account_id: the account identification
        :param reference_url: the reference URL (for remote providers, URL to obtain and validate the JWT tokens)
        :param claims: the JWT claimset, as key-value pairs
        :param access_max_age: access token duration, in seconds
        :param refresh_max_age: refresh token duration, in seconds
        :param grace_interval: time to wait for token to be valid, in seconds
        :param token_audience: the audience the token is intended for
        :param token_nonce: optional value used to associate a client session with a token
        :param request_timeout: timeout for the requests to the reference URL
        :param remote_provider: whether the JWT provider is a remote server
        :param logger: optional logger
        """
        # build and store the access data for the account
        with self.access_lock:
            if account_id not in self.access_data:
                self.access_data[account_id] = {
                    "reference-url": reference_url,
                    "access-max-age": access_max_age,
                    "refresh-max-age": refresh_max_age,
                    "grace-interval": grace_interval,
                    "token-audience": token_audience,
                    "token-nonce": token_nonce,
                    "request-timeout": request_timeout,
                    "remote-provider": remote_provider,
                    "claims": claims or {}
                }
                if logger:
                    logger.debug(f"JWT data added for '{account_id}'")
            elif logger:
                logger.warning(f"JWT data already exists for '{account_id}'")

    def remove_account(self,
                       account_id: str,
                       logger: Logger) -> bool:
        """
        Remove from storage the access data for *account_id*.

        :param account_id: the account identification
        :param logger: optional logger
        return: *True* if the access data was removed, *False* otherwise
        """
        # remove from internal storage
        account_data: dict[str, Any] | None
        with self.access_lock:
            account_data = self.access_data.pop(account_id, None)

        # remove from database
        db_delete(errors=None,
                  delete_stmt=f"DELETE FROM {JWT_DB_TABLE}",
                  where_data={JWT_DB_COL_ACCOUNT: account_id},
                  logger=logger)
        if logger:
            if account_data:
                logger.debug(f"Removed JWT data for '{account_id}'")
            else:
                logger.warning(f"No JWT data found for '{account_id}'")

        return account_data is not None

    def issue_tokens(self,
                     account_id: str,
                     account_claims: dict[str, Any] = None,
                     logger: Logger = None) -> dict[str, Any]:
        """
        Issue and return the JWT access and refresh tokens for *account_id*.

        Structure of the return data:
        {
          "access_token": <jwt-token>,
          "created_in": <timestamp>,
          "expires_in": <seconds-to-expiration>,
          "refresh_token": <jwt-token>
        }

        :param account_id: the account identification
        :param account_claims: if provided, may supercede registered account-related claims
        :param logger: optional logger
        :return: the JWT token data, or *None* if error
        :raises InvalidTokenError: token is invalid
        :raises InvalidKeyError: authentication key is not in the proper format
        :raises ExpiredSignatureError: token and refresh period have expired
        :raises InvalidSignatureError: signature does not match the one provided as part of the token
        :raises ImmatureSignatureError: 'nbf' or 'iat' claim represents a timestamp in the future
        :raises InvalidAudienceError: 'aud' claim does not match one of the expected audience
        :raises InvalidAlgorithmError: the specified algorithm is not recognized
        :raises InvalidIssuerError: 'iss' claim does not match the expected issuer
        :raises InvalidIssuedAtError: 'iat' claim is non-numeric
        :raises MissingRequiredClaimError: a required claim is not contained in the claimset
        :raises RuntimeError: error accessing the token database
        """
        # initialize the return variable
        result: dict[str, Any] | None = None

        # process the data in storage
        with (self.access_lock):
            account_data: dict[str, Any] = self.access_data.get(account_id)

            # was the JWT data obtained ?
            if account_data:
                # yes, proceed
                errors: list[str] = []
                current_claims: dict[str, Any] = account_data.get("claims").copy()
                if account_claims:
                    current_claims.update(account_claims)
                current_claims["jti"] = str_random(size=32,
                                                   chars=string.ascii_letters + string.digits)
                current_claims["sub"] = account_id
                current_claims["iss"] = account_data.get("reference-url")

                # where is the JWT service provider ?
                if account_data.get("remote-provider"):
                    # JWT service is being provided by a remote server
                    # Structure of the return data:
                    # {
                    #   "access_token": <jwt-token>,
                    #   "created_in": <timestamp>,
                    #   "expires_in": <seconds-to-expiration>,
                    #   "refresh_token": <jwt-token>
                    #   ...
                    # }
                    result = _jwt_request_token(errors=errors,
                                                reference_url=current_claims.get("iss"),
                                                claims=current_claims,
                                                timeout=account_data.get("request-timeout"),
                                                logger=logger)
                    if errors:
                        raise RuntimeError("; ".join(errors))
                else:
                    # JWT service is being provided locally
                    just_now: int = int(datetime.now(tz=timezone.utc).timestamp())
                    current_claims["iat"] = just_now

                    # issue a candidate refresh token first, and persist it
                    current_claims["exp"] = just_now + account_data.get("refresh-max-age")
                    current_claims["valid-from"] = datetime.fromtimestamp(timestamp=current_claims["iat"],
                                                                          tz=timezone.utc).isoformat()
                    current_claims["valid-until"] = datetime.fromtimestamp(timestamp=current_claims["exp"],
                                                                           tz=timezone.utc).isoformat()
                    # may raise an exception
                    refresh_token: str = jwt.encode(payload=current_claims,
                                                    key=JWT_ENCODING_KEY,
                                                    algorithm=JWT_DEFAULT_ALGORITHM)
                    # obtain a DB connection (may raise an exception)
                    db_conn: Any = db_connect(errors=errors,
                                              logger=logger)
                    # persist the candidate token (may raise an exception)
                    token_id: int = _jwt_persist_token(errors=errors,
                                                       account_id=account_id,
                                                       jwt_token=refresh_token,
                                                       db_conn=db_conn,
                                                       logger=logger)
                    # issue the definitive refresh token
                    refresh_token = jwt.encode(payload=current_claims,
                                               key=JWT_ENCODING_KEY,
                                               algorithm=JWT_DEFAULT_ALGORITHM,
                                               headers={"kid": str(token_id)})
                    # persist it
                    db_update(errors=errors,
                              update_stmt=f"UPDATE {JWT_DB_TABLE}",
                              update_data={JWT_DB_COL_TOKEN: refresh_token},
                              where_data={JWT_DB_COL_KID: token_id},
                              connection=db_conn,
                              logger=logger)
                    # commit the transaction
                    db_commit(errors=errors,
                              connection=db_conn,
                              logger=logger)
                    if errors:
                        raise RuntimeError("; ".join(errors))

                    # issue the access token
                    current_claims["exp"] = just_now + account_data.get("access-max-age")
                    # may raise an exception
                    access_token: str = jwt.encode(payload=current_claims,
                                                   key=JWT_ENCODING_KEY,
                                                   algorithm=JWT_DEFAULT_ALGORITHM)
                    # return the token data
                    result = {
                        "access_token": access_token,
                        "created_in": current_claims.get("iat"),
                        "expires_in": current_claims.get("exp"),
                        "refresh_token": refresh_token
                    }
            else:
                # JWT access data not found
                err_msg: str = f"No JWT access data found for '{account_id}'"
                if logger:
                    logger.error(err_msg)
                raise RuntimeError(err_msg)

        return result


def _jwt_request_token(errors: list[str],
                       reference_url: str,
                       claims: dict[str, Any],
                       timeout: int = None,
                       logger: Logger = None) -> dict[str, Any]:
    """
    Obtain and return the JWT token from *reference_url*, along with its duration.

    Expected structure of the return data:
    {
      "access_token": <jwt-token>,
      "created_in": <timestamp>,
      "expires_in": <seconds-to-expiration>,
      "refresh_token": <token>
    }
    It is up to the invoker to make sure that the *claims* data conform to the requirements
    of the provider issuing the JWT token.

    :param errors: incidental errors
    :param reference_url: the reference URL for obtaining JWT tokens
    :param claims: the JWT claimset, as expected by the issuing server
    :param timeout: request timeout, in seconds (defaults to *None*)
    :param logger: optional logger
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    # request the JWT token
    if logger:
        logger.debug(f"POST request JWT token to '{reference_url}'")
    response: Response = requests.post(
        url=reference_url,
        json=claims,
        timeout=timeout
    )

    # was the request successful ?
    if response.status_code in [200, 201, 202]:
        # yes, save the access token data returned
        result = response.json()
        if logger:
            logger.debug(f"JWT token obtained: {result}")
    else:
        # no, report the problem
        err_msg: str = f"POST request to '{reference_url}' failed: {response.reason}"
        if response.text:
            err_msg += f" - {response.text}"
        if logger:
            logger.error(err_msg)
        errors.append(err_msg)

    return result


def _jwt_persist_token(errors: list[str],
                       account_id: str,
                       jwt_token: str,
                       db_conn: Any = None,
                       logger: Logger = None) -> int:
    """
    Persist the given token, making sure that the account limit is adhered to.

    The tokens in storage, associated with *account_id*, are examined for their expiration timestamp.
    If a token's expiration timestamp is in the past, it is removed from storage. If the maximum number
    of active tokens for *account_id* has been reached, the oldest active one is alse removed,
    to make room for the new *jwt_token*.

    If *db_conn* is provided, then all DB operations will be carried out in the scope of a single transaction.

    :param errors: incidental errors
    :param account_id: the account identification
    :param jwt_token: the JWT token to persist
    :param db_conn: the database connection to use
    :param logger: optional logger
    :return: the storage id of the inserted token
    :raises RuntimeError: error accessing the revocation database
    """
    from pypomes_db import db_select, db_insert, db_delete
    from .jwt_pomes import jwt_get_claims

    # retrieve the account's tokens
    # noinspection PyTypeChecker
    recs: list[tuple[int, str, str, str]] = \
        db_select(errors=errors,
                  sel_stmt=f"SELECT {JWT_DB_COL_KID}, {JWT_DB_COL_TOKEN} "
                           f"FROM {JWT_DB_TABLE}",
                  where_data={JWT_DB_COL_ACCOUNT: account_id},
                  connection=db_conn)
    if errors:
        raise RuntimeError("; ".join(errors))

    if logger:
        logger.debug(msg=f"Read {len(recs)} token from storage for account '{account_id}'")
    # remove the expired tokens
    oldest: int = sys.maxsize
    surplus: int | None = None
    expired: list[int] = []
    for rec in recs:
        token: str = rec[1]
        token_kid: int = rec[0]
        token_claims: dict[str, Any] = jwt_get_claims(errors=errors,
                                                      token=token,
                                                      validate=False,
                                                      logger=logger)
        if errors:
            raise RuntimeError("; ".join(errors))

        # find expired tokens
        exp: int = token_claims["payload"].get("exp", sys.maxsize)
        if exp < datetime.now(tz=timezone.utc).timestamp():
            expired.append(token_kid)

        # find oldest token
        iat: int = token_claims["payload"].get("iat", sys.maxsize)
        if iat < oldest:
            oldest = exp
            surplus = token_kid

    # remove expired tokens from persistence
    if expired:
        db_delete(errors=errors,
                  delete_stmt=f"DELETE FROM {JWT_DB_TABLE}",
                  where_data={JWT_DB_COL_KID: expired},
                  connection=db_conn,
                  logger=logger)
        if errors:
            raise RuntimeError("; ".join(errors))
        if logger:
            logger.debug(msg=f"{len(expired)} tokens of account "
                             f"'{account_id}' removed from storage")

    if 0 < JWT_ACCOUNT_LIMIT <= len(recs) - len(expired):
        # delete the oldest token to make way for the new one
        db_delete(errors=errors,
                  delete_stmt=f"DELETE FROM {JWT_DB_TABLE}",
                  where_data={JWT_DB_COL_KID: surplus},
                  connection=db_conn,
                  logger=logger)
        if errors:
            raise RuntimeError("; ".join(errors))
        if logger:
            logger.debug(msg="Oldest active token of account "
                             f"'{account_id}' removed from storage")
    # persist token
    db_insert(errors=errors,
              insert_stmt=f"INSERT INTO {JWT_DB_TABLE}",
              insert_data={JWT_DB_COL_ACCOUNT: account_id,
                           JWT_DB_COL_TOKEN: jwt_token,
                           JWT_DB_COL_ALGORITHM: JWT_DEFAULT_ALGORITHM,
                           JWT_DB_COL_DECODER: JWT_DECODING_KEY.hex()},
              connection=db_conn,
              logger=logger)
    if errors:
        raise RuntimeError("; ".join(errors))

    # obtain the token's storage id
    reply: list[tuple[int]] = db_select(errors=errors,
                                        sel_stmt=f"SELECT {JWT_DB_COL_KID} "
                                                 f"FROM {JWT_DB_TABLE}",
                                        where_data={JWT_DB_COL_TOKEN: jwt_token},
                                        connection=db_conn,
                                        logger=logger)
    if errors:
        raise RuntimeError("; ".join(errors))

    return reply[0][0]
