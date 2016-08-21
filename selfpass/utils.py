import os
import base64

def random_hex_bytes(count):
    bytes = os.urandom(count)
    return base64.b64encode(bytes)

def generate_nonce():
    nonce = random_hex_bytes(32)
    return nonce.decode("utf-8")

def is_valid_nonce(nonce):
    #TODO actually test this (just length I guess?)
    return True
