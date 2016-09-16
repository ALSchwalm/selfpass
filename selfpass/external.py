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
        client_pub = store.get_device_public_key(js["user_id"], js["device_id"])
        signature = signature_from_dict(js["signature"])
        payload = js["payload"]

        # Verify the payload with the client's ECDSA public key
        #TODO: just use verify once cryptography 1.5 is in pip
        verifier = client_pub.verifier(signature, ec.ECDSA(hashes.SHA256()))
        verifier.update(payload.encode("utf-8"))
        verifier.verify()

        # Extract the payload (the client's ephemeral ECDH public key)
        decoded_payload = json.loads(base64.b64decode(payload).decode("utf-8"))
        client_temp_pub = public_key_from_jwk(decoded_payload["public_key"])

        # Create temporary keys and do ECDH exchange to create shared secret
        server_temp_pub, server_temp_priv = generate_key_pair()
        session_key = server_temp_priv.exchange(ec.ECDH(), client_temp_pub)[:32]

        # Generate a session ID for this handshake
        session_id = generate_session_id()

        # Derive the actual key from the ECDH value
        session_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=base64.b64decode(session_id),
            iterations=100000,
            backend=default_backend()
        ).derive(session_key)

        # Store the session key - symmetric key pair
        store.add_session_key(session_id, session_key)

        # Build and encode the response payload
        responsePayload = {
            "public_key": public_key_to_jwk(server_temp_pub),
            "session_id": session_id
        }
        encodedResponsePayload = base64.b64encode(
            json.dumps(responsePayload).encode("utf-8"))

        # Get the server's signing key
        _, server_priv = store.get_server_keys()

        # Sign the payload
        #TODO: just use sign once cryptography 1.5 is in pip
        signer = server_priv.signer(ec.ECDSA(hashes.SHA256()))
        signer.update(encodedResponsePayload)
        signature = signer.finalize()

        message = {
            "payload": encodedResponsePayload.decode("utf-8"),
            "signature": signature_to_dict(signature)
        }

        return message
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
            device_key = public_key_from_jwk(request["public_key"])
            print("Registered device key: {}".format(request["public_key"]))

            store.register_device(js["user_id"], request["device_id"], key,
                                  device_key)

            pub, _ = store.get_server_keys()

            payload = json.dumps({
                "public_key": public_key_to_jwk(pub)
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
