import jwt
import requests
from datetime import datetime, timedelta
from jwt.exceptions import ExpiredSignatureError
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
             "registered-claims": {          # registered claims
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
               "auth-type": <string>,        # HS256, HS512, RSA256, RSA512
               "request-timeout": <int>,     # in seconds - defaults to no timeout
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
                        claims: dict[str, Any],
                        service_url: str,
                        auth_type: Literal["HS256", "HS512", "RSA256", "RSA512"],
                        access_max_age: int,
                        refresh_max_age: int,
                        secret_key: bytes,
                        private_key: str,
                        public_key: str,
                        request_timeout: int,
                        local_provider: bool,
                        logger: Logger = None) -> None:
        """
        Add to storage the parameters needed to obtain and validate JWT tokens.

        :param claims: the JWT claimset, as key-value pairs
        :param service_url: the reference URL
        :param auth_type: the authentication type
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
        item_data: dict[str, dict[str, Any]] = self.retrieve_access_data(service_url=service_url)
        if not item_data:
            # build control data
            control_data: dict[str, Any] = {
                "auth-type": auth_type,
                "service-url": service_url,
                "access-max-age": access_max_age,
                "request-timeout": request_timeout,
                "local-provider": local_provider,
                "refresh-exp": datetime.now() + timedelta(seconds=refresh_max_age)
            }
            if auth_type in ["HS256", "HS512"]:
                control_data["secret-key"] = secret_key
            else:
                control_data["private-key"] = private_key
                control_data["public-key"] = public_key

            # build claims
            custom_claims: dict[str, Any] = {}
            registered_claims: dict[str, Any] = {}
            for key, value in claims:
                if key in ["nbt", "iss", "aud", "iat"]:
                    registered_claims[key] = value
                else:
                    custom_claims[key] = value
            registered_claims["exp"] = datetime(year=2000,
                                                month=1,
                                                day=1)
            # store access data
            item_data = {
                "control-data": control_data,
                "registered-claims": registered_claims,
                "custom-claims": custom_claims
            }
            with self.access_lock:
                self.access_data.append(item_data)
            if logger:
                logger.debug("JWT token data added to storage for the given parameters")
        elif logger:
            logger.warning("JWT token data already exists for the given parameters")

    def remove_access_data(self,
                           service_url: str,
                           logger: Logger) -> None:
        """
        Remove from storage the access data associated with the given parameters.

        :param service_url: the reference URL
        :param logger: optional logger
        """
        # obtain the item in storage
        item_data: dict[str, Any] = self.retrieve_access_data(service_url=service_url)
        if item_data:
            with self.access_lock:
                self.access_data.remove(item_data)
            if logger:
                logger.debug("Removed access data for the given parameters")
        elif logger:
            logger.warning("No access data found for the given parameters")

    def retrieve_access_data(self,
                             service_url: str) -> dict[str, dict[str, Any]]:
        """
        Retrieve and return the access data in storage corresponding to the given parameters.

        :param service_url: the reference URL for obtaining JWT tokens
        :return: the corresponding item in storage, or 'None' if not found
        """
        # initialize the return variable
        result: dict[str, dict[str, Any]] | None = None

        with self.access_lock:
            for item_data in self.access_data:
                if service_url == item_data.get("control-data").get("service-url"):
                    result = item_data
                    break

        return result

    def get_token_data(self,
                       service_url: str,
                       logger: Logger = None) -> dict[str, Any]:
        """
        Obtain and return the JWT token associated with *service_url*, along with its expiration timestamp.

        Structure of the return data:
        {
          "access_token": <jwt-token>,
          "expires_in": <seconds-to-expiratio>
        }

        :param service_url: the reference URL for obtaining JWT tokens
        :param logger: optional logger
        :return: the JWT token data, or 'None' if error
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
        item_data: dict[str, Any] = self.retrieve_access_data(service_url=service_url)
        # was the JWT data obtained ?
        if item_data:
            # yes, proceed
            control_data: dict[str, Any] = item_data.get("control-data")
            custom_claims: dict[str, Any] = item_data.get("custom-claims")
            registered_claims: dict[str, Any] = item_data.get("registered-claims")
            just_now: datetime = datetime.now()

            # is the current token still valid ?
            if just_now < registered_claims.get("exp"):
                # yes, return it
                result = control_data.get("access-token")
            # is the refresh operation still standing ?
            elif just_now > control_data.get("refresh-exp"):
                # no, raise the error
                err_msg: str = "Token and refresh period expired"
                if logger:
                    logger.error(err_msg)
                raise ExpiredSignatureError(err_msg)
            else:
                # obtain a new token
                service_url: str = control_data.get("service-url")
                claims: dict[str, Any] = registered_claims.copy()
                claims.update(custom_claims)

                # where is the locus of the JWT service ?
                if control_data.get("local-provider"):
                    # JWT service is local
                    claims["exp"] = just_now + timedelta(seconds=control_data.get("access-max-age"))
                    # may raise an exception
                    token: str = jwt.encode(payload=claims,
                                            key=control_data.get("secret-key") or control_data.get("private-key"),
                                            algorithm=control_data.get("auth-type"))
                    with self.access_lock:
                        control_data["access-token"] = token
                        registered_claims["exp"] = claims.get("exp")
                    result = {
                        "access_token": token,
                        "expires_in": control_data.get("access-max-age")
                    }
                else:
                    # JWT service is remote
                    if service_url.find("?") > 0:
                        service_url = service_url[:service_url.index("?")]
                    if logger:
                        logger.debug(f"Sending REST request to {service_url}")
                    # return data:
                    # {
                    #   "access_token": <token>,
                    #   "expires_in": <seconds-to-expiration>
                    # }
                    response: Response = requests.post(
                        url=service_url,
                        json=claims,
                        timeout=control_data.get("request-timeout")
                    )
                    # was the request successful ?
                    if response.status_code in [200, 201, 202]:
                        # yes, save the access token returned
                        result = response.json()
                        if logger:
                            logger.debug(f"Access token obtained: {result}")
                        with self.access_lock:
                            control_data["access-token"] = result.get("access_token")
                            duration: int = result.get("expires_in")
                            registered_claims["exp"] = just_now + timedelta(seconds=duration)
                    else:
                        # no, raise an exception
                        err_msg: str = f"Invocation of '{service_url}' failed: {response.reason}"
                        if logger:
                            logger.error(err_msg)
                        raise RuntimeError(err_msg)
        else:
            # JWT data not found
            err_msg: str = f"No access data found for {service_url}"
            if logger:
                logger.error(err_msg)
            raise RuntimeError(err_msg)

        return result


def _validate_token(token: str) -> dict[str, Any]:
    """
    Validate the JWT *token*, and return its claimset.

    :param token: the token to be validated
    :return: the token's claimset, or 'None' if error
    :raises ExpiredSignatureError: token has expired
    """
    return jwt.decode(jwt=token)
