from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from enum import Enum, StrEnum
from pypomes_core import (
    APP_PREFIX,
    env_get_str, env_get_bytes, env_get_int, env_get_enum
)
from secrets import token_bytes


class JwtAlgorithm(StrEnum):
    """
    Supported decoding algorithms.
    """
    HS256 = "HS256"
    HS512 = "HS512"
    RS256 = "RS256"
    RS512 = "RS512"


# recommended: allow the encode and decode keys to be generated anew when app starts
_encoding_key: bytes = env_get_bytes(key=f"{APP_PREFIX}_JWT_ENCODING_KEY",
                                     encoding="base64")
_decoding_key: bytes = env_get_bytes(key=f"{APP_PREFIX}_JWT_DECODING_KEY")
# default algorithm may cause encode and decode keys to be overriden
_default_algorithm: JwtAlgorithm = env_get_enum(key=f"{APP_PREFIX}_JWT_DEFAULT_ALGORITHM",
                                                enum_class=JwtAlgorithm,
                                                def_value=JwtAlgorithm.RS256)
if _default_algorithm in [JwtAlgorithm.HS256, JwtAlgorithm.HS512]:
    if not _encoding_key:
        _encoding_key = token_bytes(nbytes=32)
    _decoding_key = _encoding_key
elif not _encoding_key or not _decoding_key:
    __priv_key: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537,
                                                         key_size=2048
                                                         if _default_algorithm == JwtAlgorithm.RS256 else 4096)
    _encoding_key = __priv_key.private_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PrivateFormat.PKCS8,
                                             encryption_algorithm=serialization.NoEncryption())
    __pub_key: RSAPublicKey = __priv_key.public_key()
    _decoding_key = __pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PublicFormat.SubjectPublicKeyInfo)


# HAZARD: instances uses must be '.value' qualified, as this is not a subclass of either 'StrEnum' or 'IntEnum'
class JwtConfig(Enum):
    """
    Parameters for JWT token issuance.
    """
    # recommended: between 5 min and 1 hour (set to 5 min)
    ACCESS_MAX_AGE = env_get_int(key=f"{APP_PREFIX}_JWT_ACCESS_MAX_AGE",
                                 def_value=300)
    ACCOUNT_LIMIT = env_get_int(key=f"{APP_PREFIX}_JWT_ACCOUNT_LIMIT",
                                def_value=5)
    DEFAULT_ALGORITHM = _default_algorithm
    ENCODING_KEY = _encoding_key
    DECODING_KEY = _decoding_key
    # recommended: at least 2 hours (set to 24 hours)
    REFRESH_MAX_AGE = env_get_int(key=f"{APP_PREFIX}_JWT_REFRESH_MAX_AGE",
                                  def_value=86400)


del _decoding_key
del _encoding_key
del _default_algorithm


# database access is not be necessary, if only handling externally provided JWT tokens
class JwtDbConfig(StrEnum):
    """
    Parameters for JWT database connection.
    """
    ENGINE = env_get_str(key=f"{APP_PREFIX}_JWT_DB_ENGINE",
                         def_value="")
    TABLE = env_get_str(key=f"{APP_PREFIX}_JWT_DB_TABLE",
                        def_value="")
    COL_ACCOUNT = env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_ACCOUNT",
                              def_value="")
    COL_ALGORITHM = env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_ALGORITHM",
                                def_value="")
    COL_DECODER = env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_DECODER",
                              def_value="")
    COL_KID = env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_KID",
                          def_value="")
    COL_TOKEN = env_get_str(key=f"{APP_PREFIX}_JWT_DB_COL_TOKEN",
                            def_value="")
