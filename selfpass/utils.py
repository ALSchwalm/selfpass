import os
import base64
import hashlib

def format_access_key(s, key_id):
    parts = []
    for i in range(0, len(s), 4):
        parts.append(s[i:i+4])
    return "{:02X}".format(key_id) + "-" + "-".join(parts)

def random_b64_bytes(count):
    bytes = os.urandom(count)
    return base64.b64encode(bytes).decode("utf-8")

def random_b32_bytes(count):
    bytes = os.urandom(count)
    return base64.b32encode(bytes).decode("utf-8")

def b64_hash(s):
    hash = hashlib.sha256(s.encode("utf-8")).digest()
    return base64.b64encode(hash).decode("utf-8")

def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')
