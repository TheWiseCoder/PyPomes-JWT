import requests
import sys
from datetime import datetime, timedelta
from logging import Logger
from pypomes_core import (
    APP_PREFIX, HTTP_POST_TIMEOUT,
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
    "expires_in": datetime(2000, 1, 1, 0, 0, 0)
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
            logger.info(f"Enviando request REST para {SECURITY_URL_GET_TOKEN}: {payload}")
        try:
            response: Response = requests.post(
                url=SECURITY_URL_GET_TOKEN,
                json=payload,
                timeout=timeout
            )
            reply: dict = {}
            if response.status_code in [200, 201, 202]:
                reply = response.json()
                if logger:
                    logger.info(f"Token de acesso recebido: {reply}")

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
                err_msg = f"Não foi possível obter token de acesso: {reply}"
        except Exception as e:
            # a operação resultou em exceção
            err_msg = f"Erro na solicitação de token: {exc_format(e, sys.exc_info())}"

    if err_msg:
        if logger:
            logger.error(err_msg)
        errors.append(err_msg)

    return result
