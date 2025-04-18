from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from enum import Enum, StrEnum
from pypomes_core import (
    APP_PREFIX,
    env_get_str, env_get_bytes, env_get_int
)
from secrets import token_bytes


# recommended: allow the encode and decode keys to be generated anew when app starts
_encoding_key: bytes = env_get_bytes(key=f"{APP_PREFIX}_JWT_ENCODING_KEY",
                                     encoding="base64url")
_decoding_key: bytes
# one of HS256, HS512, RS256, RS512
_default_algorithm: str = env_get_str(key=f"{APP_PREFIX}_JWT_DEFAULT_ALGORITHM",
                                      def_value="RS256")
if _default_algorithm in ["HS256", "HS512"]:
    if not _encoding_key:
        _encoding_key = token_bytes(nbytes=32)
    _decoding_key = _encoding_key
else:
    _decoding_key: bytes = env_get_bytes(key=f"{APP_PREFIX}_JWT_DECODING_KEY")
    if not _encoding_key or not _decoding_key:
        __priv_key: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537,
                                                             key_size=2048)
        _encoding_key = __priv_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PrivateFormat.PKCS8,
                                                 encryption_algorithm=serialization.NoEncryption())
        __pub_key: RSAPublicKey = __priv_key.public_key()
        _decoding_key = __pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)


class JwtConfig(Enum):
    """
    Parameters for JWT token issuance.
    """
    # recommended: between 5 min and 1 hour (set to 5 min)
    ACCESS_MAX_AGE: int = env_get_int(key=f"{APP_PREFIX}_JWT_ACCESS_MAX_AGE",
                                      def_value=300)
    ACCOUNT_LIMIT: int = env_get_int(key=f"{APP_PREFIX}_JWT_ACCOUNT_LIMIT",
                                     def_value=5)
    ENCODING_KEY: bytes = _encoding_key
    DECODING_KEY: bytes = _decoding_key
    DEFAULT_ALGORITHM: str = _default_algorithm
    # recommended: at least 2 hours (set to 24 hours)
    REFRESH_MAX_AGE: int = env_get_int(key=f"{APP_PREFIX}_JWT_REFRESH_MAX_AGE",
                                       def_value=86400)


class JwtDbConfig(StrEnum):
    """
    Parameters for JWT databse connection.
    """
    ENGINE: str = env_get_str(key=f"{APP_PREFIX}_JWT_DB_ENGINE")
    TABLE: str = env_get_str(key=f"{APP_PREFIX}_JWT_DB_TABLE")
    COL_ACCOUNT: str = env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_ACCOUNT")
    COL_ALGORITHM: str = env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_ALGORITHM")
    COL_DECODER: str = env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_DECODER")
    COL_KID: str = env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_KID")
    COL_TOKEN: str = env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_TOKEN")
