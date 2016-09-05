import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from .utils import *

def public_key_to_dict(public_key):
    x = public_key.public_numbers().x
    y = public_key.public_numbers().y

    return {
        "x": base64.b64encode(int_to_bytes(x)).decode("utf-8"),
        "y": base64.b64encode(int_to_bytes(y)).decode("utf-8")
    }

# FIXME: currently hard coded for SECP384R1
def public_key_from_dict(public_key_json):
    x = int.from_bytes(base64.b64decode(public_key_json["x"]), "big")
    y = int.from_bytes(base64.b64decode(public_key_json["y"]), "big")

    public_numbers = ec.EllipticCurvePublicNumbers(x, y,
                                                   ec.SECP384R1())
    return public_numbers.public_key(default_backend())

def signature_from_dict(signature_json):
    r = int.from_bytes(base64.b64decode(signature_json["r"]), "big")
    s = int.from_bytes(base64.b64decode(signature_json["s"]), "big")
    return utils.encode_dss_signature(r, s)

def signature_to_dict(signature):
    r, s = utils.decode_dss_signature(signature)
    return {
        "r": base64.b64encode(int_to_bytes(r)).decode("utf-8"),
        "s": base64.b64encode(int_to_bytes(s)).decode("utf-8"),
    }


def expand_password(password, salt, length=32*8):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8"),
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))

def generate_key_pair():
    private_key = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )

    public_key = private_key.public_key()

    return public_key, private_key

def generate_session_id():
    return base64.b64encode(os.urandom(32)).decode("utf-8")
