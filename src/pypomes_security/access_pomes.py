import requests
import sys
from datetime import datetime, timedelta
from logging import Logger
from pypomes_core import exc_format
from requests import Response
from typing import Any

from .access_data import AccessData


__access_data: AccessData = AccessData()

def access_set_parameters(service_url: str,
                          user_id: str,
                          user_pwd: str,
                          key_user_id: str,
                          key_user_pwd: str,
                          logger: Logger = None) -> None:
    """
    Set the parameters needed to obtain access tokens from *service_url*.

    :param service_url: the reference URL for obtaining access tokens
    :param user_id: id of user in request
    :param user_pwd: password of user in request
    :param key_user_id: key for sending user id in request
    :param key_user_pwd: key for sending user password in request
    :param logger: optional logger
    """
    __access_data.add_service_access(service_url=service_url,
                                     user_id=user_id,
                                     user_pwd=user_pwd,
                                     key_user_id=key_user_id,
                                     key_user_pwd=key_user_pwd,
                                     logger=logger)


def access_clear_parameters(service_url: str,
                            logger: Logger = None) -> dict[str, Any]:
    """
    Remove from storage and return the parameters associated with *service_url*.

    :param service_url: the reference URL
    :param logger: optional logger
    :return: the removed parameters, or 'None' if they were not found
    """
    return __access_data.clear_service_access(service_url=service_url,
                                              logger=logger)


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
    token, expiration, user_id, user_pwd, key_user_id, key_user_pwd = \
        __access_data.get_access_data(service_url=service_url,
                                      logger=logger)

    # has the token's expiration timestamp been obtained ?
    if expiration:
        # yes, proceed
        just_now: datetime = datetime.now()

        # is the current token still valid ?
        if just_now < expiration:
            # yes, return it
            result = token
        else:
            # no, obtain a new one
            payload: dict[str, str] = {
                key_user_id: user_id,
                key_user_pwd: user_pwd
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
                token = None
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
                    duration: int = reply.get("expires_in")
                    expiration: datetime = just_now + timedelta(seconds=duration)
                    __access_data.set_access_data(service_url=service_url,
                                                  token=token,
                                                  expiration=expiration,
                                                  logger=logger)
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
