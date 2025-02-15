import jwt
import requests
from datetime import datetime, timezone
from jwt.exceptions import InvalidTokenError
from logging import Logger
from pypomes_core import str_random
from requests import Response
from threading import Lock
from typing import Any, Literal


class JwtData:
    """
    Shared JWT data for security token access.

    Instance variables:
        - access_lock: lock for safe multi-threading access
        - access_data: list with dictionaries holding the JWT token data:
         [
           {
             "control-data": {               # control data
               "remote-provider": <bool>,    # whether the JWT provider is a remote server
               "access-token": <jwt-token>,  # access token
               "algorithm": <string>,        # HS256, HS512, RSA256, RSA512
               "request-timeout": <int>,     # in seconds - defaults to no timeout
               "access-max-age": <int>,      # in seconds - defaults to JWT_ACCESS_MAX_AGE
               "refresh-exp": <timestamp>,   # expiration time for the refresh operation
               "hs-secret-key": <bytes>,     # HS secret key
               "rsa-private-key": <bytes>,   # RSA private key
               "rsa-public-key": <bytes>,    # RSA public key
             },
             "reserved-claims": {        # reserved claims
               "exp": <timestamp>,       # expiration time
               "iat": <timestamp>        # issued at
               "iss": <string>,          # issuer (for remote providers, URL to obtain and validate the access tokens)
               "jti": <string>,          # JWT id
               "sub": <string>           # subject (the account identification)
               # not used:
               # "aud": <string>         # audience
               # "nbt": <timestamp>      # not before time
             },
             "public-claims": {          # public claims (may be empty)
               "birthdate": <string>,    # subject's birth date
               "email": <string>,        # subject's email
               "gender": <string>,       # subject's gender
               "name": <string>,         # subject's name
               "roles": <List[str]>      # subject roles
             },
             "custom-claims": {          # custom claims (may be empty)
               "<custom-claim-key-1>": "<custom-claim-value-1>",
               ...
               "<custom-claim-key-n>": "<custom-claim-value-n>"
             }
           },
           ...
         ]
    """
    def __init__(self) -> None:
        """
        Initizalize the token access data.
        """
        self.access_lock: Lock = Lock()
        self.access_data: list[dict[str, dict[str, Any]]] = []

    def add_access_data(self,
                        account_id: str,
                        reference_url: str,
                        claims: dict[str, Any],
                        algorithm: Literal["HS256", "HS512", "RSA256", "RSA512"],
                        access_max_age: int,
                        refresh_max_age: int,
                        hs_secret_key: bytes,
                        rsa_private_key: bytes,
                        rsa_public_key: bytes,
                        request_timeout: int,
                        remote_provider: bool,
                        logger: Logger = None) -> None:
        """
        Add to storage the parameters needed to produce and validate JWT tokens for *account_id*.

        The parameter *claims* may contain public and custom claims. Currently, the public claims supported
        are *birthdate*, *email*, *gender*, *name*, and *roles*. Everything else is considered to be custom
        claims, and sent to the remote JWT provided, if applicable.

        Presently, the *refresh_max_age* data is not relevant, as the authorization parameters in *claims*
        (typically, an acess-key/hs-secret-key pair), have been previously validated elsewhere.
        This situation might change in the future.

        :param account_id: the account identification
        :param reference_url: the reference URL (for remote providers, URL to obtain and validate the JWT tokens)
        :param claims: the JWT claimset, as key-value pairs
        :param algorithm: the algorithm used to sign the token with
        :param access_max_age: token duration (in seconds)
        :param refresh_max_age: duration for the refresh operation (in seconds)
        :param hs_secret_key: secret key for HS authentication
        :param rsa_private_key: private key for RSA authentication
        :param rsa_public_key: public key for RSA authentication
        :param request_timeout: timeout for the requests to the reference URL
        :param remote_provider: whether the JWT provider is a remote server
        :param logger: optional logger
        """
        # Do the access data already exist ?
        if not self.get_access_data(account_id=account_id):
            # no, build control data
            control_data: dict[str, Any] = {
                "algorithm": algorithm,
                "access-max-age": access_max_age,
                "request-timeout": request_timeout,
                "remote-provider": remote_provider,
                "refresh-exp": int(datetime.now(tz=timezone.utc).timestamp()) + refresh_max_age
            }
            if algorithm in ["HS256", "HS512"]:
                control_data["hs-secret-key"] = hs_secret_key
            else:
                control_data["rsa-private-key"] = rsa_private_key
                control_data["rsa-public-key"] = rsa_public_key

            # build claims
            reserved_claims: dict[str, Any] = {
                "sub": account_id,
                "iss": reference_url,
                "exp": 0,
                "iat": 0,
                "jti": "<jwt-id>",
            }
            custom_claims: dict[str, Any] = {}
            public_claims: dict[str, Any] = {}
            for key, value in claims.items():
                if key in ["birthdate", "email", "gender", "name", "roles"]:
                    public_claims[key] = value
                else:
                    custom_claims[key] = value
            # store access data
            item_data = {
                "control-data": control_data,
                "reserved-claims": reserved_claims,
                "public-claims": public_claims,
                "custom-claims": custom_claims
            }
            with self.access_lock:
                self.access_data.append(item_data)
            if logger:
                logger.debug(f"JWT data added for '{account_id}': {item_data}")
        elif logger:
            logger.warning(f"JWT data already exists for '{account_id}'")

    def remove_access_data(self,
                           account_id: str,
                           logger: Logger) -> None:
        """
        Remove from storage the access data for *account_id*.

        :param account_id: the account identification
        :param logger: optional logger
        """
        # obtain the access data item in storage
        item_data: dict[str, dict[str, Any]] = self.get_access_data(account_id=account_id,
                                                                    logger=logger)
        if item_data:
            with self.access_lock:
                self.access_data.remove(item_data)
            if logger:
                logger.debug(f"Removed JWT data for '{account_id}'")
        elif logger:
            logger.warning(f"No JWT data found for '{account_id}'")

    def get_token_data(self,
                       account_id: str,
                       superceding_claims: dict[str, Any] = None,
                       logger: Logger = None) -> dict[str, Any]:
        """
        Obtain and return the JWT token for *account_id*, along with its duration.

        Structure of the return data:
        {
          "access_token": <jwt-token>,
          "created_in": <timestamp>,
          "expires_in": <seconds-to-expiration>
        }

        :param account_id: the account identification
        :param superceding_claims: if provided, may supercede registered custom claims
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
        :raises RuntimeError: access data not found for the given *account_id*, or
                              the remote JWT provider failed to return a token
        """
        # declare the return variable
        result: dict[str, Any]

        # obtain the item in storage
        access_data: dict[str, Any] = self.get_access_data(account_id=account_id,
                                                           logger=logger)
        # was the JWT data obtained ?
        if access_data:
            # yes, proceed
            control_data: dict[str, Any] = access_data.get("control-data")
            reserved_claims: dict[str, Any] = access_data.get("reserved-claims")
            custom_claims: dict[str, Any] = access_data.get("custom-claims")
            if superceding_claims:
                custom_claims = custom_claims.copy()
                custom_claims.update(superceding_claims)

            # obtain a new token, if the current token has expired
            just_now: int = int(datetime.now(tz=timezone.utc).timestamp())
            if just_now > reserved_claims.get("exp"):
                # where is the JWT service provider ?
                if control_data.get("remote-provider"):
                    # JWT service is being provided by a remote server
                    errors: list[str] = []
                    # Structure of the return data:
                    # {
                    #   "access_token": <jwt-token>,
                    #   "created_in": <timestamp>,
                    #   "expires_in": <seconds-to-expiration>,
                    #   ...
                    # }
                    reply: dict[str, Any] = jwt_request_token(errors=errors,
                                                              reference_url=reserved_claims.get("iss"),
                                                              claims=custom_claims,
                                                              timeout=control_data.get("request-timeout"),
                                                              logger=logger)
                    if reply:
                        with self.access_lock:
                            control_data["access-token"] = reply.get("access_token")
                            reserved_claims["jti"] = str_random(size=16)
                            reserved_claims["iat"] = reply.get("created_in")
                            reserved_claims["exp"] = reply.get("created_in") + reply.get("expires_in")
                    else:
                        raise RuntimeError(" - ".join(errors))
                else:
                    # JWT service is being provided locally
                    claims: dict[str, Any] = access_data.get("public-claims").copy()
                    claims.update(reserved_claims)
                    claims.update(custom_claims)
                    # may raise an exception
                    token: str = jwt.encode(payload=claims,
                                            key=(control_data.get("hs-secret-key") or
                                                 control_data.get("rsa-private-key")),
                                            algorithm=control_data.get("algorithm"))
                    with self.access_lock:
                        reserved_claims["jti"] = str_random(size=16)
                        reserved_claims["iat"] = just_now
                        reserved_claims["exp"] = just_now + control_data.get("access-max-age")
                        control_data["access-token"] = token

            # return the token
            result = {
                "access_token": control_data.get("access-token"),
                "created_in": reserved_claims.get("iat"),
                "expires_in": reserved_claims.get("exp") - reserved_claims.get("iat")
            }
        else:
            # JWT access data not found
            err_msg: str = f"No JWT access data found for '{account_id}'"
            if logger:
                logger.error(err_msg)
            raise RuntimeError(err_msg)

        return result

    def get_token_claims(self,
                         token: str,
                         logger: Logger = None) -> dict[str, Any]:
        """
        Obtain and return the claims of a JWT *token*.

        :param token: the token to be inspected for claims
        :param logger: optional logger
        :return: the token's claimset, or *None* if error
        :raises InvalidTokenError: token is not valid
        :raises ExpiredSignatureError: token has expired
        :raises InvalidAlgorithmError: the specified algorithm is not recognized
        """
        # declare the return variable
        result: dict[str, Any]

        if logger:
            logger.debug(msg=f"Retrieve claims for JWT token '{token}'")

        access_data: dict[str, Any] = self.get_access_data(access_token=token,
                                                           logger=logger)
        if access_data:
            control_data: dict[str, Any] = access_data.get("control-data")
            if control_data.get("remote-provider"):
                # provider is remote
                result = control_data.get("custom-claims")
            else:
                # may raise an exception
                result = jwt.decode(jwt=token,
                                    key=(control_data.get("hs-secret-key") or
                                         control_data.get("rsa-public-key")),
                                    algorithms=[control_data.get("algorithm")])
        else:
            raise InvalidTokenError("JWT token is not valid")

        if logger:
            logger.debug(f"Retrieved claims for JWT token '{token}': {result}")

        return result

    def get_access_data(self,
                        account_id: str = None,
                        access_token: str = None,
                        logger: Logger = None) -> dict[str, dict[str, Any]]:
        # noinspection HttpUrlsUsage
        """
        Retrieve and return the access data in storage for *account_id*, or optionally, for *access_token*.

        Either *account_id* or *access_token* must be provided, the former having precedence over the later.
        Note that, whereas *account_id* uniquely identifies an access dataset, *access_token* might not,
        and thus, the first dataset associated with it would be returned.

        :param account_id: the account identification
        :param access_token: the access token
        :param logger: optional logger
        :return: the corresponding item in storage, or *None* if not found
        """
        # initialize the return variable
        result: dict[str, dict[str, Any]] | None = None
    
        if logger:
            target: str = f"account id '{account_id}'" if account_id else f"token '{access_token}'"
            logger.debug(f"Retrieve access data for {target}")
        # retrieve the data
        with self.access_lock:
            for item_data in self.access_data:
                if (account_id and account_id == item_data.get("reserved-claims").get("sub")) or \
                        (access_token and access_token == item_data.get("control-data").get("access-token")):
                    result = item_data
                    break
        if logger:
            logger.debug(f"Data is '{result}'")

        return result


def jwt_request_token(errors: list[str],
                      reference_url: str,
                      claims: dict[str, Any],
                      timeout: int = None,
                      logger: Logger = None) -> dict[str, Any]:
    """
    Obtain and return the JWT token from *reference_url*, along with its duration.

    Expected structure of the return data:
    {
      "access_token": <jwt-token>,
      "expires_in": <seconds-to-expiration>
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


def jwt_validate_token(token: str,
                       key: bytes | str,
                       algorithm: str,
                       logger: Logger = None) -> None:
    """
    Verify if *token* ia a valid JWT token.

    Raise an appropriate exception if validation failed.

    :param token: the token to be validated
    :param key: the secret or public key used to create the token (HS or RSA authentication, respectively)
    :param algorithm: the algorithm used to to sign the token with
    :param logger: optional logger
    :raises InvalidTokenError: token is invalid
    :raises InvalidKeyError: authentication key is not in the proper format
    :raises ExpiredSignatureError: token and refresh period have expired
    :raises InvalidSignatureError: signature does not match the one provided as part of the token
    """
    if logger:
        logger.debug(msg=f"Validate JWT token '{token}'")
    jwt.decode(jwt=token,
               key=key,
               algorithms=[algorithm])
    if logger:
        logger.debug(msg=f"Token '{token}' is valid")
