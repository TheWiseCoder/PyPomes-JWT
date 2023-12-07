import requests
import sys
from datetime import datetime, timedelta
from logging import Logger
from pypomes_core import (
    APP_PREFIX, HTTP_POST_TIMEOUT, TIMEZONE_LOCAL,
    env_get_str, exc_format
)
from requests import Response
from typing import Final

SECURITY_TAG_USER_ID: Final[str] = env_get_str(f"{APP_PREFIX}_SECURITY_TAG_USER_ID")
SECURITY_TAG_USER_PWD: Final[str] = env_get_str(f"{APP_PREFIX}_SECURITY_TAG_USER_PWD")
SECURITY_URL_GET_TOKEN: Final[str] = env_get_str(f"{APP_PREFIX}_SECURITY_URL_GET_TOKEN")
SECURITY_USER_ID: Final[str] = env_get_str(f"{APP_PREFIX}_SECURITY_USER_ID")
SECURITY_USER_PWD: Final[str] = env_get_str(f"{APP_PREFIX}_SECURITY_USER_PWD")

__access_token: dict = {
    "access_token": None,
    "expires_in": datetime(year=2000,
                           month=1,
                           day=1,
                           tzinfo=TIMEZONE_LOCAL)
}


def access_get_token(errors: list[str],
                     timeout: int | None = HTTP_POST_TIMEOUT, logger: Logger = None) -> str:
    """
    Obtain and return an access token for further interaction with a protected resource.

    The current token is inspected to determine whether its expiration timestamp requires
    it to be refreshed.

    :param errors: incidental error messages
    :param timeout: timeout, in seconds (defaults to HTTP_POST_TIMEOUT - use None to omit)
    :param logger: optional logger to log the operation with
    :return: the access token
    """
    # inicialize the return variable
    result: str | None = None

    just_now: datetime = datetime.now(TIMEZONE_LOCAL)
    err_msg: str | None = None

    # is the current token still valid ?
    if just_now < __access_token["expires_in"]:
        # yes, return it
        result = __access_token.get("access_token")
    else:
        # no, retrieve a new one
        payload: dict = {
            SECURITY_TAG_USER_ID: SECURITY_USER_ID,
            SECURITY_TAG_USER_PWD: SECURITY_USER_PWD
        }

        # send the REST request
        if logger:
            logger.info(f"Sending REST request to {SECURITY_URL_GET_TOKEN}: {payload}")
        try:
            response: Response = requests.post(
                url=SECURITY_URL_GET_TOKEN,
                json=payload,
                timeout=timeout
            )
            reply: dict | str
            if response.status_code in [200, 201, 202]:
                reply = response.json()
                if logger:
                    logger.info(f"Access token obtained: {reply}")
            else:
                reply = response.reason
            # has the request succeeded ?
            token: str = reply.get("access_token")
            if token is not None and len(token) > 0:
                # yes, proceed
                __access_token["access_token"] = token
                duration: int = reply.get("expires_in")
                __access_token["expires_in"] = just_now + timedelta(seconds=duration)
                result = token
            else:
                # não, report the problem
                err_msg = f"Unable to obtain access token: {reply}"
        except Exception as e:
            # the operation raised an exception
            err_msg = f"Error obtaining access token: {exc_format(e, sys.exc_info())}"

    if err_msg:
        if logger:
            logger.error(err_msg)
        errors.append(err_msg)

    return result
