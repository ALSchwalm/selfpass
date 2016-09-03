import os
import base64
import json
from .utils import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def symmetric_encrypt(key, plaintext):
    iv = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(encryptor.tag).decode("utf-8")
    }

def symmetric_decrypt(db, ciphertext_json):
    key = db.get_access_key_by_id(ciphertext_json["user_id"],
                                  int(ciphertext_json["access_key_id"], 16))

    iv = base64.b64decode(ciphertext_json["iv"])
    tag = base64.b64decode(ciphertext_json["tag"])
    ciphertext = base64.b64decode(ciphertext_json["ciphertext"])

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        default_backend()
    ).decryptor()

    return key, decryptor.update(ciphertext) + decryptor.finalize()

VALID_REQUEST_METHODS = {
    "update-keystore",
    "retrieve-keystore"
}

def validate_request(request):

    # All requests must have some method
    if "request" not in request:
        return False, "Missing request method"

    if request["request"] not in VALID_REQUEST_METHODS:
        return False, "Unknown request method"

    # All requests must have a request nonce
    if "request-nonce" not in request:
        return False, "No request-nonce"

    # Request nonce's must be valid
    if not is_valid_nonce(request["request-nonce"]):
        return False, "Invalid request-nonce"

    return True, None

def handle_request(db, js):

    valid_status, reason = validate_request(request)
    if valid_status is False:
        return "", 204

    method = request["request"]

    if method == "retrieve-keystore":
        store = db.get_keystore_by_id(user[1])
        response = {
            "response": "OK",
            "request-nonce": request["request-nonce"],
            "data": store
        }
    elif method == "update-keystore":
        db.update_user_keystore(user[1], request["data"])
        response = {
            "response": "OK",
            "request-nonce": request["request-nonce"],
        }
    else:
        response = ""

    return encrypt_as_user(user[1], user[2], json.dumps(response).encode("utf-8"))

def handle_pair_request(store, js):
    # First do the decryption on the crypto-layer and get the actual request
    try:
        key, payload = symmetric_decrypt(store, js)
        request = json.loads(payload.decode("utf-8"))

        if request["request"] == "register-device":
            pub, _ = store.get_server_keys()

            x = pub.public_numbers().x
            y = pub.public_numbers().y
            print(x)
            print(y)

            payload = json.dumps({
                "ecc": {
                    "x": base64.b64encode(int_to_bytes(x)).decode("utf-8"),
                    "y": base64.b64encode(int_to_bytes(y)).decode("utf-8")
                }
            }).encode("utf-8")
            return symmetric_encrypt(key, payload)
    except Exception:
        import traceback
        traceback.print_exc()
        return "", 400

def run(store):
    from flask import Flask, request, jsonify
    from flask_cors import CORS

    external = Flask("selfpass-external")
    CORS(external)

    @external.route("/", methods=["POST"])
    def external_route():
        res = handle_request(store, request.get_json())
        if isinstance(res, tuple):
            return res
        return jsonify(res)

    @external.route("/pair", methods=["POST"])
    def pair():
        res = handle_pair_request(store, request.get_json())
        if isinstance(res, tuple):
            return res
        return jsonify(res)
    external.run(port=4999)
