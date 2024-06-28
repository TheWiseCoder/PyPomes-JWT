from datetime import datetime
from logging import Logger
from threading import Lock
from typing import Any

class AccessData:
    """
    Shared data for security token access.

    Instance variables:
        - access_lock: lock for safe multi-threading access
        - access_data: dictionary holding the token access data:
         {
           <access_url> = {
             "token": <access-token>,
             "expiration": <datetime>,
             "key_user_id": <key-user-id>,
             "key_user_pwd": <key-user-pwd>,
             "user_id": <user-id>,
             "user_pwd": <user-pwd>
           },
           ...
         }
    """
    def __init__(self) -> None:
        """
        Initizalize the token access structure.
        """
        self.access_lock: Lock = Lock()
        self.access_data: dict[str, Any] = {}

    def add_service_access(self,
                           service_url: str,
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
        with self.access_lock:
            if not hasattr(self.access_data, service_url):
                token_data: dict[str, Any] = {
                    "token": None,
                    "expiration": datetime(year=2000,
                                           month=1,
                                           day=1),
                    "key-user-id": key_user_id,
                    "key-user-pwd": key_user_pwd,
                    "user-id": user_id,
                    "user-pwd": user_pwd
                }
                self.access_data[service_url] = token_data
                if logger:
                    logger.debug("Access token data set for "
                                 f"'{service_url}': {token_data}")
            elif logger:
                logger.warning(f"Access token data already exists for '{service_url}'")

    def clear_service_access(self,
                             service_url: str,
                             logger: Logger = None) -> dict[str, Any]:
        """
        Remove from storage and return the parameters associated with *service_url*.

        :param service_url: the reference URL for obtaining access tokens
        :param logger: optional logger
        """
        # initialize the return variable
        result: dict[str, Any] | None = None
        with self.access_lock:
            if hasattr(self.access_data, service_url):
                result = self.access_data.pop(service_url)
                if logger:
                    logger.debug(f"Cleared access data for '{service_url}'")
            elif logger:
                logger.warning(f"No access data defined for '{service_url}")

        return result


    def get_access_data(self,
                        service_url: str,
                        logger: Logger = None) -> tuple[str, datetime, str, str, str, str]:
        """
        Retrieve the token from *service_url*, along with its expiration timestamp.

        :param service_url: the reference URL for obtaining the access token
        :param logger: optional logger
        :return: a tuple holding the token and its expiration timestamp
        """
        # initialize the return variable
        result: tuple[str, datetime, str, str, str, str] | None = None

        with self.access_lock:
            token_data: dict[str, Any] = self.access_data.get(service_url)
            if token_data:
                result = (token_data.get("token"), token_data.get("expiration"),
                          token_data.get("user-id"), token_data.get("user-pwd"),
                          token_data.get("key-user-id"), token_data.get("keyuser-pwd"))
            elif logger:
                logger.error(f"No access data defined for '{service_url}")

        return result

    def set_access_data(self,
                        service_url: str,
                        token: str,
                        expiration: datetime,
                        logger: Logger = None) -> None:
        """
        Set the token for *service_url*, along with its expiration timestamp.

        :param service_url: the reference URL for obtaining the access token
        :param token: the access token
        :param expiration: the token's expiration timestamp
        :param logger: optional logger
        """
        with self.access_lock:
            token_data = self.access_data.get(service_url)
            if token_data:
                token_data["token"] = token
                token_data["expiration"] = expiration
            elif logger:
                logger.error(f"No access data defined for '{service_url}")
