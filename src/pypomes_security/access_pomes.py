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

    # inicializa a variável de retorno
    result: str | None = None

    global __access_token
    agora: datetime = datetime.now()
    err_msg: str | None = None

    # obtem um novo token, se o atual estiver expirado
    if agora > __access_token["expires_in"]:
        # monta o payload do request
        payload: dict = {
            SECURITY_TAG_USER_ID: SECURITY_USER_ID,
            SECURITY_TAG_USER_PWD: SECURITY_USER_PWD
        }

        # envia o request REST
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
            # o request foi bem sucedido ?
            token: str = reply.get("access_token")
            if token is not None and len(token) > 0:
                # sim, prossiga
                __access_token["access_token"] = token
                duration: int = reply.get("expires_in")
                __access_token["expires_in"] = agora + timedelta(seconds=duration)
                result = token
            else:
                # não, reporte o problema
                err_msg = f"Unable to obtain access token: {reply}"
        except Exception as e:
            # a operação resultou em exceção
            err_msg = f"Error obtaining access token: {exc_format(e, sys.exc_info())}"

    if err_msg:
        if logger:
            logger.error(err_msg)
        errors.append(err_msg)

    return result
