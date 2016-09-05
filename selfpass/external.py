import os
import base64
import json
from .utils import *
from .crypto import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
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


def handle_request(store, js):
    pass

def handle_hello(store, js):
    try:
        pub = store.get_device_public_key(js["user_id"], js["device_id"])
        print("public_key:", public_key_to_dict(pub))

        signature = signature_from_dict(js["signature"])

        payload = js["payload"]

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(payload.encode("utf-8"))
        print("Computed hash: {}".format(base64.b64encode(digest.finalize())))

        #TODO: just use verify once cryptography 1.5 is in pip
        verifier = pub.verifier(signature, ec.ECDSA(hashes.SHA256()))
        verifier.update(payload.encode("utf-8"))
        verifier.verify()

        print("verified")
        return "", 200
    except:
        import traceback
        traceback.print_exc()
        return "", 400

def handle_pair(store, js):
    # First do the decryption on the crypto-layer and get the actual request
    try:
        key, payload = symmetric_decrypt(store, js)
        request = json.loads(payload.decode("utf-8"))

        if request["request"] == "register-device":
            device_key = public_key_from_dict(request["public_key"])
            print("Registered device key: {}".format(request["public_key"]))

            store.register_device(js["user_id"], request["device_id"], key,
                                  device_key)

            pub, _ = store.get_server_keys()

            payload = json.dumps({
                "public_key": public_key_to_dict(pub)
            }).encode("utf-8")

            return symmetric_encrypt(key, payload)
        else:
            return "", 400
    except Exception:
        import traceback
        traceback.print_exc()
        return "", 400

def run(store):
    from flask import Flask, request, jsonify
    from flask_cors import CORS

    external = Flask("selfpass-external")
    CORS(external)

    @external.route("/request", methods=["POST"])
    def request_route():
        res = handle_request(store, request.get_json())
        if isinstance(res, tuple):
            return res
        return jsonify(res)

    @external.route("/hello", methods=["POST"])
    def hello_route():
        res = handle_hello(store, request.get_json())
        if isinstance(res, tuple):
            return res
        return jsonify(res)

    @external.route("/pair", methods=["POST"])
    def pair_route():
        res = handle_pair(store, request.get_json())
        if isinstance(res, tuple):
            return res
        return jsonify(res)
    external.run(port=4999)
