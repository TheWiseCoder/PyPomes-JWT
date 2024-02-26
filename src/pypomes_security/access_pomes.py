import requests
import sys
from datetime import datetime, timedelta
from logging import Logger
from pypomes_core import (
    APP_PREFIX, TIMEZONE_LOCAL,
    env_get_str, exc_format
)
from requests import Response

SECURITY_KEY_USER_ID: str = env_get_str(f"{APP_PREFIX}_SECURITY_TAG_USER_ID")
SECURITY_KEY_USER_PWD: str = env_get_str(f"{APP_PREFIX}_SECURITY_TAG_USER_PWD")
SECURITY_URL_GET_TOKEN: str = env_get_str(f"{APP_PREFIX}_SECURITY_URL_GET_TOKEN")
SECURITY_USER_ID: str = env_get_str(f"{APP_PREFIX}_SECURITY_USER_ID")
SECURITY_USER_PWD: str = env_get_str(f"{APP_PREFIX}_SECURITY_USER_PWD")


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
__access_tokens: dict = {}


def access_set_url_data(service_url: str,
                        user_id: str, user_pwd: str,
                        key_user_id: str, key_user_pwd: str) -> None:
    """
    Set the parameters to use in the service invocation to obtain the access token for *service_url*.

    Note that one set of parameters can optionally be provided as environment variables.

    :param service_url: the reference URL for obtaining the access token
    :param user_id: id of user in request
    :param user_pwd: password of user in request
    :param key_user_id: key for sending user id in request
    :param key_user_pwd: key for sending user password in request
    """
    # build the access token structure
    url_token_data: dict = {
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

    # save it to the global repository
    __access_tokens[service_url] = url_token_data


def access_remove_url_data(service_url: str) -> dict:
    """
    Remove from storage and return the parameters associated with *service_url*.

    :param service_url: the reference URL
    """
    return __access_tokens.pop(service_url)


def access_get_token(errors: list[str], service_url: str,
                     timeout: int | None = None, logger: Logger = None) -> str:
    """
    Obtain and return an access token for further interaction with a protected resource.

    The current token is inspected to determine whether its expiration timestamp requires
    it to be refreshed.

    :param errors: incidental error messages
    :param service_url: request URL for the access token
    :param timeout: timeout, in seconds (defaults to HTTP_POST_TIMEOUT - use None to omit)
    :param logger: optional logger to log the operation with
    :return: the access token
    """
    # inicialize the return variable
    result: str | None = None

    # initialize the local error message
    err_msg: str | None = None

    # obtain the token data for the given URL
    url_token_data: dict = __get_url_token_data(service_url)

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
                logger.info(f"Sending REST request to {service_url}")
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
                reply: dict | str
                token: str | None = None
                # was the request successful ?
                if response.status_code in [200, 201, 202]:
                    # yes, retrieve the access token returned
                    reply = response.json()
                    token = reply.get("access_token")
                    if logger:
                        logger.info(f"Access token obtained: {reply}")
                else:
                    # no, retrieve the reason for the failure
                    reply = response.reason

                # was the access token retrieved ?
                if token is not None and len(token) > 0:
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
        errors.append(err_msg)

    return result


def __get_url_token_data(service_url: str) -> dict:

    # obtain the data for the given service URL
    result: dict = __access_tokens.get(service_url)

    # no data found for URL, but environment data matches it ?
    if not result and service_url == SECURITY_URL_GET_TOKEN:
        # yes, store the data
        access_set_url_data(service_url,
                            SECURITY_USER_ID, SECURITY_USER_PWD,
                            SECURITY_KEY_USER_ID, SECURITY_KEY_USER_PWD)
        result: dict = __access_tokens.get(service_url)

    return result
