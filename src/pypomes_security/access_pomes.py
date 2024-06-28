import requests
import sys
from datetime import datetime, timedelta
from logging import Logger
from pypomes_core import TIMEZONE_LOCAL, exc_format
from requests import Response
from typing import Any


# initial data for <access_url> in '__access_tokens':
# {
#   <access_url> = {
#     "token": None,
#     "expiration": datetime(year=2000,
#                            month=1,
#                            day=1,
#                            tzinfo=TIMEZONE_LOCAL),
#     "key_user_id": <key-user-id>,
#     "key_user_pwd": <key-user-pwd>,
#     "user_id": <user-id>,
#     "user_pwd": <user-pwd>
#   },
#   ...
# }
__access_tokens: dict[str, dict[str, Any]] = {}


def access_set_parameters(service_url: str,
                          user_id: str,
                          user_pwd: str,
                          key_user_id: str,
                          key_user_pwd: str,
                          logger: Logger = None) -> None:
    """
    Set the parameters to use in the service invocation to obtain the access token for *service_url*.

    :param service_url: the reference URL for obtaining the access token
    :param user_id: id of user in request
    :param user_pwd: password of user in request
    :param key_user_id: key for sending user id in request
    :param key_user_pwd: key for sending user password in request
    :param logger: optional logger
    """
    # build the access token structure
    url_token_data: dict[str, Any] = {
        "token": None,
        "expiration": datetime(year=2000,
                               month=1,
                               day=1,
                               tzinfo=TIMEZONE_LOCAL),
        "key_user_id": key_user_id,
        "key_user_pwd": key_user_pwd,
        "user_id": user_id,
        "user_pwd": user_pwd
    }
    if logger:
        logger.debug("Access token data set for "
                     f"'{service_url}': {url_token_data}")

    # save it to the global repository
    __access_tokens[service_url] = url_token_data


def access_clear_parameters(service_url: str,
                            logger: Logger = None) -> dict[str, Any]:
    """
    Remove from storage and return the parameters associated with *service_url*.

    :param service_url: the reference URL
    :param logger: optional logger
    :return: the removed parameters, or 'None' if they were not found
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    if logger:
        logger.debug(f"Access token data clear requested for '{service_url}'")

    if hasattr(__access_tokens, service_url):
        result = __access_tokens.pop(service_url)
        if logger:
            logger.debug(f"Access token data cleared for '{service_url}'")

    return result


def access_get_token(errors: list[str],
                     service_url: str,
                     timeout: int = None,
                     logger: Logger = None) -> str:
    """
    Obtain and return an access token for further interaction with a protected resource.

    The current token is inspected to determine whether its expiration timestamp requires
    it to be refreshed.

    :param errors: incidental error messages
    :param service_url: request URL for the access token
    :param timeout: timeout, in seconds (defaults to HTTP_POST_TIMEOUT - use None to omit)
    :param logger: optional logger
    :return: the access token
    """
    # inicialize the return variable
    result: str | None = None

    # initialize the local error message
    err_msg: str | None = None

    # obtain the token data for the given URL
    url_token_data: dict[str, Any] = __access_tokens.get(service_url)

    # has the token data been obtained ?
    if url_token_data:
        # yes, proceed
        token_expiration: datetime = url_token_data.get("expiration")

        # establish the current date and time
        just_now: datetime = datetime.now(TIMEZONE_LOCAL)

        # is the current token still valid ?
        if just_now < token_expiration:
            # yes, return it
            result = url_token_data.get("token")
        else:
            # no, retrieve a new one
            payload: dict = {
                url_token_data.get("key_user_id"): url_token_data.get("user_id"),
                url_token_data.get("key_user_pwd"): url_token_data.get("user_pwd")
            }

            # send the REST request
            if logger:
                logger.debug(f"Sending REST request to {service_url}")
            try:
                # return data:
                # {
                #   "access_token": <token>,
                #   "expires_in": <seconds-to-expiration>
                # }
                response: Response = requests.post(
                    url=service_url,
                    json=payload,
                    timeout=timeout
                )
                reply: dict[str, Any] | str
                token: str | None = None
                # was the request successful ?
                if response.status_code in [200, 201, 202]:
                    # yes, retrieve the access token returned
                    reply = response.json()
                    token = reply.get("access_token")
                    if logger:
                        logger.debug(f"Access token obtained: {reply}")
                else:
                    # no, retrieve the reason for the failure
                    reply = response.reason

                # was the access token retrieved ?
                if token:
                    # yes, proceed
                    url_token_data["token"] = token
                    duration: int = reply.get("expires_in")
                    url_token_data["expiration"] = just_now + timedelta(seconds=duration)
                    result = token
                else:
                    # no, report the problem
                    err_msg = f"Unable to obtain access token: {reply}"
            except Exception as e:
                # the operation raised an exception
                err_msg = f"Error obtaining access token: {exc_format(e, sys.exc_info())}"
    else:
        # no, report the problem
        err_msg = f"Parameters for obtaining access token from '{service_url}' have not been defined"

    if err_msg:
        if logger:
            logger.error(err_msg)
        if isinstance(errors, list):
            errors.append(err_msg)

    return result
