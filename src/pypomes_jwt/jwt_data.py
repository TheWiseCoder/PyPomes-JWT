import jwt
import math
import requests
from datetime import datetime, timedelta, timezone
from jwt.exceptions import InvalidTokenError
from logging import Logger
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
             "standard-claims": {            # standard claims
               "exp": <timestamp>,           # expiration time
               "nbt": <timestamp>,           # not before time
               "iss": <string>,              # issuer
               "aud": <string>,              # audience
               "iat": <string>               # issued at
             },
             "custom-claims": {              # custom claims
               "<custom-claim-key-1>": "<custom-claim-value-1>",
               ...
               "<custom-claim-key-n>": "<custom-claim-value-n>"
             },
             "control-data": {               # control data
               "access-token": <jwt-token>,  # access token
               "algorithm": <string>,        # HS256, HS512, RSA256, RSA512
               "request-timeout": <float>,   # in seconds - defaults to no timeout
               "access-max-age": <int>,      # in seconds - defaults to JWT_ACCESS_MAX_AGE
               "refresh-exp": <timestamp>,   # expiration time for the refresh operation
               "service-url": <url>,         # URL to obtain and validate the access tokens
               "local-provider": <bool>,     # whether 'service-url' is a local endpoint
               "secret-key": <bytes>,        # HS secret key
               "private-key": <bytes>,       # RSA private key
               "public-key": <bytes>,        # RSA public key
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
                        service_url: str,
                        claims: dict[str, Any],
                        algorithm: Literal["HS256", "HS512", "RSA256", "RSA512"],
                        access_max_age: int,
                        refresh_max_age: int,
                        secret_key: bytes,
                        private_key: bytes,
                        public_key: bytes,
                        request_timeout: float,
                        local_provider: bool,
                        logger: Logger = None) -> None:
        """
        Add to storage the parameters needed to obtain and validate JWT tokens.

        Protocol indication in *service_url* (typically *http:* or *https:*), is disregarded, to guarantee
        that processing herein will not be affected by in-transit protocol changes.

        Presently, the *refresh_max_age* data is not relevant, as the authorization parameters in *claims*
        (typically, an acess-key/secret-key pair), have been previously validated elsewhere.
        This situation might change in the future.

        :param service_url: the reference URL
        :param claims: the JWT claimset, as key-value pairs
        :param algorithm: the algorithm used to sign the token with
        :param access_max_age: token duration
        :param refresh_max_age: duration for the refresh operation
        :param secret_key: secret key for HS authentication
        :param private_key: private key for RSA authentication
        :param public_key: public key for RSA authentication
        :param request_timeout: timeout for the requests to the service URL
        :param local_provider: whether 'service_url' is a local endpoint
        :param logger: optional logger
        """
        # obtain the item in storage
        item_data: dict[str, dict[str, Any]] = self.retrieve_access_data(service_url=service_url,
                                                                         logger=logger)
        if not item_data:
            # build control data
            control_data: dict[str, Any] = {
                "service-url": service_url,
                "algorithm": algorithm,
                "access-max-age": access_max_age,
                "request-timeout": request_timeout,
                "local-provider": local_provider,
                "refresh-exp": datetime.now(tz=timezone.utc) + timedelta(seconds=refresh_max_age)
            }
            if algorithm in ["HS256", "HS512"]:
                control_data["secret-key"] = secret_key
            else:
                control_data["private-key"] = private_key
                control_data["public-key"] = public_key

            # build claims
            custom_claims: dict[str, Any] = {}
            standard_claims: dict[str, Any] = {}
            for key, value in claims.items():
                if key in ["nbt", "iss", "aud", "iat"]:
                    standard_claims[key] = value
                else:
                    custom_claims[key] = value
            standard_claims["exp"] = datetime(year=2000,
                                              month=1,
                                              day=1,
                                              tzinfo=timezone.utc)
            # store access data
            item_data = {
                "control-data": control_data,
                "standard-claims": standard_claims,
                "custom-claims": custom_claims
            }
            with self.access_lock:
                self.access_data.append(item_data)
            if logger:
                logger.debug(f"JWT data added for '{service_url}': {item_data}")
        elif logger:
            logger.warning(f"JWT data already exists for '{service_url}'")

    def remove_access_data(self,
                           service_url: str,
                           logger: Logger) -> None:
        """
        Remove from storage the access data associated with the given parameters.

        :param service_url: the reference URL
        :param logger: optional logger
        """
        # obtain the item in storage
        item_data: dict[str, dict[str, Any]] = self.retrieve_access_data(service_url=service_url,
                                                                         logger=logger)
        if item_data:
            with self.access_lock:
                self.access_data.remove(item_data)
            if logger:
                logger.debug(f"Removed JWT data for '{service_url}'")
        elif logger:
            logger.warning(f"No JWT data found for '{service_url}'")

    def get_token_data(self,
                       service_url: str,
                       logger: Logger = None) -> dict[str, Any]:
        """
        Obtain and return the JWT token associated with *service_url*, along with its duration.

        Structure of the return data:
        {
          "access_token": <jwt-token>,
          "expires_in": <seconds-to-expiration>
        }

        :param service_url: the reference URL for obtaining JWT tokens
        :param logger: optional logger
        :return: the JWT token data, or 'None' if error
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
        :raises RuntimeError: access data not found for the given 'service_url', or
                              the remote JWT provider failed to return a token
        """
        # declare the return variable
        result: dict[str, Any]

        # obtain the item in storage
        item_data: dict[str, Any] = self.retrieve_access_data(service_url=service_url,
                                                              logger=logger)
        # was the JWT data obtained ?
        if item_data:
            # yes, proceed
            control_data: dict[str, Any] = item_data.get("control-data")
            custom_claims: dict[str, Any] = item_data.get("custom-claims")
            standard_claims: dict[str, Any] = item_data.get("standard-claims")
            just_now: datetime = datetime.now(tz=timezone.utc)

            # is the current token still valid ?
            if just_now > standard_claims.get("exp"):
                # no, obtain a new token
                service_url: str = control_data.get("service-url")
                claims: dict[str, Any] = standard_claims.copy()
                claims.update(custom_claims)

                # where is the locus of the JWT service ?
                if control_data.get("local-provider"):
                    # JWT service is local
                    claims["exp"] = just_now + timedelta(seconds=control_data.get("access-max-age") + 10)
                    # may raise an exception
                    token: str = jwt.encode(payload=claims,
                                            key=control_data.get("secret-key") or control_data.get("private-key"),
                                            algorithm=control_data.get("algorithm"))
                    with self.access_lock:
                        control_data["access-token"] = token
                        standard_claims["exp"] = claims.get("exp")
                else:
                    # JWT service is remote
                    if service_url.find("?") > 0:
                        service_url = service_url[:service_url.index("?")]
                    claims.pop("exp", None)
                    errors: list[str] = []
                    result = jwt_request_token(errors=errors,
                                               service_url=service_url,
                                               claims=claims,
                                               timeout=control_data.get("request-timeout"),
                                               logger=logger)
                    if result:
                        with self.access_lock:
                            control_data["access-token"] = result.get("access_token")
                            duration: int = result.get("expires_in")
                            standard_claims["exp"] = just_now + timedelta(seconds=duration)
                    else:
                        raise RuntimeError(" - ".join(errors))

            # return the token
            diff: timedelta = standard_claims.get("exp") - just_now - timedelta(seconds=10)
            result = {
                "access_token": control_data.get("access-token"),
                "expires_in": math.trunc(diff.total_seconds())
            }
        else:
            # JWT data not found
            err_msg: str = f"No JWT data found for {service_url}"
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
        :return: the token's claimset, or 'None' if error
        :raises InvalidTokenError: token is not valid
        :raises ExpiredSignatureError: token has expired
        """
        algorithm: str | None = None
        key: str | None = None
        with self.access_lock:
            for item_data in self.access_data:
                control_data: dict[str, Any] = item_data.get("control-data")
                if token == control_data.get("access-token"):
                    algorithm = control_data.get("algorithm")
                    key = control_data.get("public-key") or control_data.get("secret-key")
                    break

        if not algorithm or not key:
            raise InvalidTokenError("JWT token is not valid")

        if logger:
            logger.debug(msg=f"Retrieve claims for JWT token '{token}'")
        result: dict[str, Any] = jwt.decode(jwt=token,
                                            key=key,
                                            algorithms=[algorithm])
        if logger:
            logger.debug(f"Retrieved claims for JWT token '{token}': {result}")

        return result

    def retrieve_access_data(self,
                             service_url: str,
                             logger: Logger = None) -> dict[str, dict[str, Any]]:
        """
        Retrieve and return the access data in storage corresponding to *service_url*.

        Protocol indication in *service_url* (typically *http:* or *https:*), is disregarded, to guarantee
        that processing herein will not be affected by in-transit protocol changes.

        :param service_url: the reference URL for obtaining JWT tokens
        :param logger: optional logger
        :return: the corresponding item in storage, or 'None' if not found
        """
        # initialize the return variable
        result: dict[str, dict[str, Any]] | None = None

        # disregard protocol
        if service_url.find("://") > 0:
            service_url = service_url[service_url.index("://")+3:]

        with self.access_lock:
            for item_data in self.access_data:
                item_url: str = item_data.get("control-data").get("service-url")
                if item_url.find("://") > 0:
                    item_url = item_url[item_url.index("://")+3:]
                if service_url == item_url:
                    result = item_data
                    break
        if logger:
            logger.debug(f"JWT data for '{service_url}': {result}")

        return result


def jwt_request_token(errors: list[str],
                      service_url: str,
                      claims: dict[str, Any],
                      timeout: float = None,
                      logger: Logger = None) -> dict[str, Any]:
    """
    Obtain and return the JWT token associated with *service_url*, along with its duration.

    Expected structure of the return data:
    {
      "access_token": <jwt-token>,
      "expires_in": <seconds-to-expiration>
    }
    It is up to the invoker to make sure that the *claims* data conform to the requirements
    of the provider issuing the JWT token.

    :param errors: incidental errors
    :param service_url: the reference URL for obtaining JWT tokens
    :param claims: the JWT claimset, as expected by the issuing server
    :param timeout: request timeout, in seconds (defaults to 'None')
    :param logger: optional logger
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    # request the JWT token
    if logger:
        logger.debug(f"POST request JWT token to '{service_url}'")
    response: Response = requests.post(
        url=service_url,
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
        err_msg: str = f"POST request of '{service_url}' failed: {response.reason}"
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
        logger.debug(msg=f"Verify request for JWT token '{token}'")
    jwt.decode(jwt=token,
               key=key,
               algorithms=[algorithm])
