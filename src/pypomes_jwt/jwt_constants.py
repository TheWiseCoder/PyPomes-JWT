from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from enum import StrEnum
from pypomes_core import (
    APP_PREFIX,
    env_get_str, env_get_bytes, env_get_int
)
from pypomes_db import DbEngine, db_setup
from secrets import token_bytes
from sys import stderr
from typing import Any, Final


class JwtParam(StrEnum):
    """
    Parameters for JWT provider access.
    """
    ACCESS_MAX_AGE = "access-max-age"
    ACCOUNT_LIMIT = "account-limit"
    DECODING_KEY = "decoding-key"
    DEFAULT_ALGORITHM = "default-algorithm"
    ENCODING_KEY = "encoding-key"
    REFRESH_MAX_AGE = "refresh-max-age"

    def __str__(self) -> str:  # noqa: D105
        # noinspection PyTypeChecker
        return self.value


class JwtDbParam(StrEnum):
    """
    Parameters for JWT databse connection.
    """
    CLIENT = "client"
    DRIVER = "driver"
    ENGINE = "engine"
    NAME = "name"
    HOST = "host"
    PORT = "port"
    USER = "user"
    PWD = "pwd"
    TABLE = "table"
    COL_ACCOUNT = "col-account"
    COL_ALGORITHM = "col-algorithm"
    COL_DECODER = "col-decoder"
    COL_KID = "col-kid"
    COL_TOKEN = "col-token"

    def __str__(self) -> str:  # noqa: D105
        # noinspection PyTypeChecker
        return self.value


# recommended: allow the encode and decode keys to be generated anew when app starts
__encoding_key: bytes = env_get_bytes(key=f"{APP_PREFIX}_JWT_ENCODING_KEY",
                                      encoding="base64url")
__decoding_key: bytes
# one of HS256, HS512, RS256, RS512
__default_algorithm: str = env_get_str(key=f"{APP_PREFIX}_JWT_DEFAULT_ALGORITHM",
                                       def_value="RS256")
if __default_algorithm in ["HS256", "HS512"]:
    if not __encoding_key:
        __encoding_key = token_bytes(nbytes=32)
    __decoding_key = __encoding_key
else:
    __decoding_key: bytes = env_get_bytes(key=f"{APP_PREFIX}_JWT_DECODING_KEY")
    if not __encoding_key or not __decoding_key:
        __priv_key: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537,
                                                             key_size=2048)
        __encoding_key = __priv_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PrivateFormat.PKCS8,
                                                  encryption_algorithm=serialization.NoEncryption())
        __pub_key: RSAPublicKey = __priv_key.public_key()
        __decoding_key = __pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PublicFormat.SubjectPublicKeyInfo)

_JWT_CONFIG: Final[dict[JwtParam, Any]] = {
    # recommended: between 5 min and 1 hour (set to 5 min)
    JwtParam.ACCESS_MAX_AGE: env_get_int(key=f"{APP_PREFIX}_JWT_ACCESS_MAX_AGE",
                                         def_value=300),
    JwtParam.ACCOUNT_LIMIT: env_get_int(key=f"{APP_PREFIX}_JWT_ACCOUNT_LIMIT"),
    JwtParam.DECODING_KEY: __decoding_key,
    JwtParam.DEFAULT_ALGORITHM: __default_algorithm,
    JwtParam.ENCODING_KEY: __encoding_key,
    # recommended: at least 2 hours (set to 24 hours)
    JwtParam.REFRESH_MAX_AGE: env_get_int(key=f"{APP_PREFIX}_JWT_REFRESH_MAX_AGE",
                                          def_value=86400)
}
_JWT_DATABASE: Final[JwtDbParam, Any] = {
    JwtDbParam.ENGINE: DbEngine(env_get_str(key=f"{APP_PREFIX}_JWT_DB_ENGINE")),
    JwtDbParam.CLIENT: env_get_str(key=f"{APP_PREFIX}_JWT_DB_CLIENT"),  # for Oracle, only
    JwtDbParam.DRIVER: env_get_str(key=f"{APP_PREFIX}_JWT_DB_DRIVER"),  # for SQLServer, only
    JwtDbParam.NAME: env_get_str(key=f"{APP_PREFIX}_JWT_DB_NAME"),
    JwtDbParam.HOST: env_get_str(key=f"{APP_PREFIX}_JWT_DB_HOST"),
    JwtDbParam.PORT: env_get_int(key=f"{APP_PREFIX}_JWT_DB_PORT"),
    JwtDbParam.USER: env_get_str(key=f"{APP_PREFIX}_JWT_DB_USER"),
    JwtDbParam.PWD: env_get_str(key=f"{APP_PREFIX}_JWT_DB_PWD"),
    JwtDbParam.TABLE:  env_get_str(key=f"{APP_PREFIX}_JWT_DB_TABLE"),
    JwtDbParam.COL_ACCOUNT: env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_ACCOUNT"),
    JwtDbParam.COL_ALGORITHM: env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_ALGORITHM"),
    JwtDbParam.COL_DECODER: env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_DECODER"),
    JwtDbParam.COL_KID: env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_KID"),
    JwtDbParam.COL_TOKEN: env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_TOKEN")
}

# define and validate the database engine
if not db_setup(engine=_JWT_DATABASE[JwtDbParam.ENGINE],
                db_name=_JWT_DATABASE[JwtDbParam.NAME],
                db_user=_JWT_DATABASE[JwtDbParam.USER],
                db_pwd=_JWT_DATABASE[JwtDbParam.PWD],
                db_host=_JWT_DATABASE[JwtDbParam.HOST],
                db_port=_JWT_DATABASE[JwtDbParam.PORT],
                db_client=_JWT_DATABASE[JwtDbParam.CLIENT],
                db_driver=_JWT_DATABASE[JwtDbParam.DRIVER]):
    stderr.write("Invalid database parameters\n")
