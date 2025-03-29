import jwt
import string
import sys
from base64 import urlsafe_b64encode
from datetime import datetime, timezone
from logging import Logger
from pypomes_core import str_random
from pypomes_db import (
    DbEngine, db_connect, db_commit, db_rollback,
    db_select, db_insert, db_update, db_delete
)
from threading import Lock
from typing import Any

from .jwt_configuration import JwtConfig, JwtDbConfig


class JwtRegistry:
    """
    Shared JWT registry for security token access.

    Instance variables:
      - access_lock: lock for safe multi-threading access
      - access_data: dictionary holding the JWT token data, organized by account id:
       {
         <account-id>: {
           "access-max-age": <int>,         # defaults to JWT_ACCESS_MAX_AGE (in seconds)
           "refresh-max-age": <int>,        # defaults to JWT_REFRESH_MAX_AGE (in seconds)
           "grace-interval": <int>,         # time to wait for token to be valid, in seconds
           "claims": {
             "iss": <string>,               # token'ss issuer
             "birthdate": <string>,         # subject's birth date
             "email": <string>,             # subject's email
             "gender": <string>,            # subject's gender
             "name": <string>,              # subject's name
             "roles": <List[str]>,          # subject roles
             "nonce": <string>,             # used to associate a Client session with a token
             # output, only
             "valid-from": <string>,        # token's start (<YYYY-MM-DDThh:mm:ss+00:00>)
             "valid-until": <string>,       # token's finish (<YYYY-MM-DDThh:mm:ss+00:00>)
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
      # required
      "exp": <timestamp>        expiration time
      "iat": <timestamp>        issued at
      "iss": <string>           token's issuer
      "jti": <string>           JWT id
      "sub": <string>           subject (the account identification)
      # optional
      "aud": <string>           token audience
      "nbt": <timestamp>        not before time

    Account-related claims are optional claims, and convey information about the registered account they belong to.
    Alhough they can be freely specified, these are some of the most commonly used claims:
       "valid-from": <string>   token's start (<YYYY-MM-DDThh:mm:ss+00:00>)
       "valid-until": <string>  token's finish (<YYYY-MM-DDThh:mm:ss+00.00>)
       "birthdate": <string>    subject's birth date
       "email": <string>        subject's email
       "gender": <string>       subject's gender
       "name": <string>         subject's name
       "roles": <List[str]>     subject roles
       "nonce": <string>        used to associate a client session with a token

    The token header has these items:
      "alg": <string>           the algorithm used to sign the token (one of *HS256*, *HS51*', *RSA256*, *RSA512*)
      "typ": <string>           the token type (fixed to *JWT*)
      "kid": <string>           a token type and key to its location in the token database

    If issued by the local server, "kid" holds the key to the corresponding record in the token database,
    if starting with *A* for (*Access*) or *R* (for *Refresh*), followed an integer.
    """
    def __init__(self) -> None:
        """
        Initizalize the token access data.
        """
        self.access_lock: Lock = Lock()
        self.access_registry: dict[str, Any] = {}

    def add_account(self,
                    account_id: str,
                    claims: dict[str, Any],
                    access_max_age: int,
                    refresh_max_age: int,
                    grace_interval: int | None,
                    logger: Logger = None) -> None:
        """
        Add to storage the parameters needed to produce and validate JWT tokens for *account_id*.

        The parameter *claims* may contain account-related claims, only. Ideally, it should contain,
        at a minimum, *iss*, *birthdate*, *email*, *gender*, *name*, and *roles*.
        The parameter *refresh_max_age* should be at least 300 seconds greater than *access-max-age*.

        :param account_id: the account identification
        :param claims: the JWT claimset, as key-value pairs
        :param access_max_age: access token duration, in seconds (at least 60 seconds)
        :param refresh_max_age: refresh token duration, in seconds (greater than *access_max_age*)
        :param grace_interval: time to wait for token to be valid, in seconds
        :param logger: optional logger
        """
        # build and store the access data for the account
        with self.access_lock:
            if account_id not in self.access_registry:
                self.access_registry[account_id] = {
                    "access-max-age": access_max_age,
                    "refresh-max-age": refresh_max_age,
                    "grace-interval": grace_interval,
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
            account_data = self.access_registry.pop(account_id, None)

        # remove from database
        db_delete(errors=None,
                  delete_stmt=f"DELETE FROM {JwtDbConfig}",
                  where_data={JwtDbConfig.COL_ACCOUNT: account_id},
                  engine=DbEngine(JwtDbConfig.ENGINE),
                  logger=logger)
        if logger:
            if account_data:
                logger.debug(f"Removed JWT data for '{account_id}'")
            else:
                logger.warning(f"No JWT data found for '{account_id}'")

        return account_data is not None

    def issue_token(self,
                    account_id: str,
                    nature: str,
                    duration: int,
                    grace_interval: int = None,
                    claims: dict[str, Any] = None,
                    logger: Logger = None) -> str:
        """
        Issue an return a JWT token associated with *account_id*.

        The parameter *nature* must be a single letter in the range *[B-Z]*, less *R*
        (*A* is reserved for *access* tokens, and *R* for *refresh* tokens).
        The parameter *duration* specifies the token's validity interval (at least 60 seconds).
        These claims are ignored, if specified in *claims*: *iat*, *iss*, *exp*, *jti*, *nbf*, and *sub*.

        :param account_id: the account identification
        :param nature: the token's nature, must be a single letter in the range *[B-Z]*, less *R*
        :param duration: the number of seconds for the token to remain valid (at least 60 seconds)
        :param claims: optional token's claims
        :param grace_interval: optional interval for the token to become active (in seconds)
        :param logger: optional logger
        :return: the JWT token
        :raises RuntimeError: invalid parameter
        """
        # validate some parameters
        err_msg: str | None = None
        if not isinstance(nature, str) or \
                len(nature) != 1 or nature < "A" or nature > "Z":
            err_msg: str = f"Invalid nature '{nature}'"
        elif not isinstance(duration, int) or duration < 60:
            err_msg = f"Invalid duration '{duration}'"
        if err_msg:
            if logger:
                logger.error(err_msg)
            raise RuntimeError(err_msg)

        # obtain the account data in storage (may raise an exception)
        account_data: dict[str, Any] = self.__get_account_data(account_id=account_id,
                                                               logger=logger)
        # issue the token
        current_claims: dict[str, Any] = {}
        iss: str = account_data["claims"].get("iss")
        if iss:
            current_claims["iss"] = iss
        if claims:
            current_claims.update(claims)

        current_claims["jti"] = str_random(size=32,
                                           chars=string.ascii_letters + string.digits)
        current_claims["sub"] = account_id
        just_now: int = int(datetime.now(tz=timezone.utc).timestamp())
        current_claims["iat"] = just_now
        if grace_interval:
            current_claims["nbf"] = just_now + grace_interval
            current_claims["valid-from"] = datetime.fromtimestamp(timestamp=current_claims["nbf"],
                                                                  tz=timezone.utc).isoformat()
        else:
            current_claims["valid-from"] = datetime.fromtimestamp(timestamp=current_claims["iat"],
                                                                  tz=timezone.utc).isoformat()
        current_claims["exp"] = just_now + duration
        current_claims["valid-until"] = datetime.fromtimestamp(timestamp=current_claims["exp"],
                                                               tz=timezone.utc).isoformat()
        # may raise an exception
        return jwt.encode(payload=current_claims,
                          key=JwtConfig.ENCODING_KEY.value,
                          algorithm=JwtConfig.DEFAULT_ALGORITHM.value,
                          headers={"kid": nature})

    def issue_tokens(self,
                     account_id: str,
                     account_claims: dict[str, Any] = None,
                     db_conn: Any = None,
                     logger: Logger = None) -> dict[str, Any]:
        """
        Issue and return a JWT token pair associated with *account_id*.

        These claims are ignored, if specified in *account_claims*: *iat*, *exp*, *jti*, *nbf*, and *sub*.
        Other claims specified therein may supercede registered account-related claims.

        If provided, *db_conn* indicates that this operation is part of a larger database transaction.
        Otherwise, the database transaction's scope is limited to this operation.

        Structure of the return data:
        {
          "access-token": <jwt-token>,
          "created-in": <timestamp>,
          "expires-in": <seconds-to-expiration>,
          "refresh-token": <jwt-token>
        }

        :param account_id: the account identification
        :param account_claims: if provided, may supercede registered account-related claims
        :param db_conn: if provided, indicates that this operation is part of a larger database transaction
        :param logger: optional logger
        :return: the JWT token data
        :raises RuntimeError: invalid account id, or error accessing the token database
        """
        # process the account data in storage
        with (self.access_lock):
            account_data: dict[str, Any] = self.__get_account_data(account_id=account_id,
                                                                   logger=logger)
            current_claims: dict[str, Any] = account_data["claims"].copy()
            if account_claims:
                current_claims.update(account_claims)
            current_claims["jti"] = str_random(size=32,
                                               chars=string.ascii_letters + string.digits)
            current_claims["sub"] = account_id
            errors: list[str] = []

            just_now: int = int(datetime.now(tz=timezone.utc).timestamp())
            current_claims["iat"] = just_now
            grace_interval = account_data.get("grace-interval")
            if grace_interval:
                current_claims["nbf"] = just_now + grace_interval
                current_claims["valid-from"] = datetime.fromtimestamp(timestamp=current_claims["nbf"],
                                                                      tz=timezone.utc).isoformat()
            else:
                current_claims["valid-from"] = datetime.fromtimestamp(timestamp=current_claims["iat"],
                                                                      tz=timezone.utc).isoformat()
            # issue a candidate refresh token first, and persist it
            current_claims["exp"] = just_now + account_data.get("refresh-max-age")
            current_claims["valid-until"] = datetime.fromtimestamp(timestamp=current_claims["exp"],
                                                                   tz=timezone.utc).isoformat()
            # may raise an exception
            refresh_token: str = jwt.encode(payload=current_claims,
                                            key=JwtConfig.ENCODING_KEY.value,
                                            algorithm=JwtConfig.DEFAULT_ALGORITHM.value,
                                            headers={"kid": "R0"})

            # make sure to have a database connection
            curr_conn: Any = db_conn or db_connect(errors=errors,
                                                   autocommit=False,
                                                   engine=DbEngine(JwtDbConfig.ENGINE),
                                                   logger=logger)
            if curr_conn:
                # persist the candidate token (may raise an exception)
                token_id: int = _jwt_persist_token(account_id=account_id,
                                                   jwt_token=refresh_token,
                                                   db_conn=curr_conn,
                                                   logger=logger)
                # issue the definitive refresh token
                refresh_token = jwt.encode(payload=current_claims,
                                           key=JwtConfig.ENCODING_KEY.value,
                                           algorithm=JwtConfig.DEFAULT_ALGORITHM.value,
                                           headers={"kid": f"R{token_id}"})
                # persist it
                db_update(errors=errors,
                          update_stmt=f"UPDATE {JwtDbConfig.TABLE}",
                          update_data={JwtDbConfig.COL_TOKEN: refresh_token},
                          where_data={JwtDbConfig.COL_KID: token_id},
                          engine=DbEngine(JwtDbConfig.ENGINE),
                          connection=curr_conn,
                          committable=False,
                          logger=logger)

                # wrap-up the transaction
                if not db_conn:
                    if errors:
                        db_rollback(errors=errors,
                                    connection=curr_conn,
                                    logger=logger)
                    else:
                        db_commit(errors=errors,
                                  connection=curr_conn,
                                  logger=logger)
            if errors:
                raise RuntimeError("; ".join(errors))

            # issue the access token
            current_claims["exp"] = just_now + account_data.get("access-max-age")
            # may raise an exception
            access_token: str = jwt.encode(payload=current_claims,
                                           key=JwtConfig.ENCODING_KEY.value,
                                           algorithm=JwtConfig.DEFAULT_ALGORITHM.value,
                                           headers={"kid": f"A{token_id}"})
            # return the token data
            return {
                "access-token": access_token,
                "created-in": current_claims.get("iat"),
                "expires-in": current_claims.get("exp"),
                "refresh-token": refresh_token
            }

    def __get_account_data(self,
                           account_id: str,
                           logger: Logger = None) -> dict[str, Any]:
        """
        Retrieve the JWT access data associated with *account_id*.

        :return: the JWT access data associated with *account_id*
        :raises RuntimeError: No JWT access data exists for *account_id*
        """
        # retrieve the access data
        result: dict[str, Any] = self.access_registry.get(account_id)
        if not result:
            # JWT access data not found
            err_msg: str = f"No JWT access data found for '{account_id}'"
            if logger:
                logger.error(err_msg)
            raise RuntimeError(err_msg)

        return result


def _jwt_persist_token(account_id: str,
                       jwt_token: str,
                       db_conn: Any,
                       logger: Logger = None) -> int:
    """
    Persist the given token, making sure that the account limit is complied with.

    The tokens in storage, associated with *account_id*, are examined for their expiration timestamp.
    If a token's expiration timestamp is in the past, it is removed from storage. If the maximum number
    of active tokens for *account_id* has been reached, the oldest active one is alse removed,
    to make room for the new *jwt_token*.
    The provided database connection *db_conn* indicates that this operation is part of a larger transaction.

    :param account_id: the account identification
    :param jwt_token: the JWT token to persist
    :param db_conn: the database connection to use
    :param logger: optional logger
    :return: the storage id of the inserted token
    :raises RuntimeError: error accessing the token database
    """
    from .jwt_pomes import jwt_get_claims

    # retrieve the account's tokens
    errors: list[str] = []
    # noinspection PyTypeChecker
    recs: list[tuple[int, str, str, str]] = \
        db_select(errors=errors,
                  sel_stmt=f"SELECT {JwtDbConfig.COL_KID}, {JwtDbConfig.COL_TOKEN} "
                           f"FROM {JwtDbConfig.TABLE}",
                  where_data={JwtDbConfig.COL_ACCOUNT: account_id},
                  engine=DbEngine(JwtDbConfig.ENGINE),
                  connection=db_conn,
                  committable=False,
                  logger=logger)
    if errors:
        raise RuntimeError("; ".join(errors))

    if logger:
        logger.debug(msg=f"Read {len(recs)} token from storage for account '{account_id}'")
    # remove the expired tokens
    just_now: int = int(datetime.now(tz=timezone.utc).timestamp())
    oldest_ts: int = sys.maxsize
    oldest_id: int | None = None
    existing_ids: list[int] = []
    expired: list[int] = []
    for rec in recs:
        token: str = rec[1]
        token_id: int = rec[0]
        token_payload: dict[str, Any] = (jwt_get_claims(errors=errors,
                                                        token=token,
                                                        logger=logger) or {}).get("payload")
        if errors:
            raise RuntimeError("; ".join(errors))

        # find expired tokens
        exp: int = token_payload.get("exp", sys.maxsize)
        if exp < just_now:
            expired.append(token_id)

        # find oldest token
        iat: int = token_payload.get("iat", sys.maxsize)
        if iat < oldest_ts:
            oldest_ts = iat
            oldest_id = token_id

        # save token id
        existing_ids.append(token_id)

    # remove expired tokens from persistence
    if expired:
        db_delete(errors=errors,
                  delete_stmt=f"DELETE FROM {JwtDbConfig.TABLE}",
                  where_data={JwtDbConfig.COL_KID: expired},
                  engine=DbEngine(JwtDbConfig.ENGINE),
                  connection=db_conn,
                  committable=False,
                  logger=logger)
        if errors:
            raise RuntimeError("; ".join(errors))
        if logger:
            logger.debug(msg=f"{len(expired)} tokens of account "
                             f"'{account_id}' removed from storage")

    if 0 < JwtConfig.ACCOUNT_LIMIT.value <= len(recs) - len(expired):
        # delete the oldest token to make way for the new one
        db_delete(errors=errors,
                  delete_stmt=f"DELETE FROM {JwtDbConfig.TABLE}",
                  where_data={JwtDbConfig.COL_KID: oldest_id},
                  engine=DbEngine(JwtDbConfig.ENGINE),
                  connection=db_conn,
                  committable=False,
                  logger=logger)
        if errors:
            raise RuntimeError("; ".join(errors))
        if logger:
            logger.debug(msg="Oldest active token of account "
                             f"'{account_id}' removed from storage")
    # persist token
    db_insert(errors=errors,
              insert_stmt=f"INSERT INTO {JwtDbConfig.TABLE}",
              insert_data={
                  JwtDbConfig.COL_ACCOUNT: account_id,
                  JwtDbConfig.COL_TOKEN: jwt_token,
                  JwtDbConfig.COL_ALGORITHM: JwtConfig.DEFAULT_ALGORITHM.value,
                  JwtDbConfig.COL_DECODER: urlsafe_b64encode(s=JwtConfig.DECODING_KEY.value).decode()
              },
              engine=DbEngine(JwtDbConfig.ENGINE),
              connection=db_conn,
              committable=False,
              logger=logger)
    if errors:
        raise RuntimeError("; ".join(errors))

    # obtain and return the token's storage id
    # HAZARD: JWT_DB_COL_TOKEN's column type might prevent it for being used in a WHERE clause
    where_clause: str | None = None
    if existing_ids:
        where_clause = f"{JwtDbConfig.COL_KID} NOT IN {existing_ids}"
        where_clause = where_clause.replace("[", "(", 1).replace("]", ")", 1)
    reply: list[tuple[int]] = db_select(errors=errors,
                                        sel_stmt=f"SELECT {JwtDbConfig.COL_KID} "
                                                 f"FROM {JwtDbConfig.TABLE}",
                                        where_clause=where_clause,
                                        where_data={JwtDbConfig.COL_ACCOUNT: account_id},
                                        require_count=1,
                                        engine=DbEngine(JwtDbConfig.ENGINE),
                                        connection=db_conn,
                                        committable=False,
                                        logger=logger)
    if errors:
        raise RuntimeError("; ".join(errors))

    return reply[0][0]
