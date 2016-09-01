import sqlite3
import os
import random
from .utils import *
from .crypto import expand_password
from collections import namedtuple


def connected(func):
    def inner(self, *args):
        conn = sqlite3.connect(self.path)
        res = func(self, conn, conn.cursor(), *args)
        conn.commit()
        return res
    return inner

class Store(object):
    def __init__(self, path):
        self.path = path

        if not os.path.isfile(self.path):
            self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.path)
        conn.cursor().executescript("""
        CREATE TABLE users (
            user_id  TEXT PRIMARY KEY,
            username TEXT,
            keystore TEXT
        );

        CREATE TABLE active_keys (
            user_id       TEXT,
            access_key    TEXT,
            access_key_id INTEGER PRIMARY KEY,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        );

        CREATE TABLE devices (
            user_id     TEXT,
            device_id   TEXT,
            device_name TEXT,
            public_key  TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        );
        """)
        conn.commit()

    @connected
    def get_user_by_id(self, conn, cursor, id):
        res = cursor.execute("""
        SELECT username, user_id, access_key, keystore FROM users WHERE id = ?
        """, (id,))

        if res is None:
            raise ValueError("No user with id: '{}'".format(id))

        return res.fetchone()

    @connected
    def get_user_by_name(self, conn, cursor, username):
        res = cursor.execute("""
        SELECT username, user_id, keystore FROM users WHERE username = ?
        """, (username,)).fetchone()

        if res is None:
            raise ValueError("No such user: '{}'".format(username))
        return res

    @connected
    def get_keystore_by_id(self, conn, cursor, id):
        return self.get_user_by_id(id)[2]

    @connected
    def get_access_key_by_id(self, conn, cursor, user_id, access_key_id):
        print(user_id, access_key_id)
        res = cursor.execute("""
        SELECT access_key FROM active_keys WHERE
        user_id = ? AND access_key_id = ?
        """, (user_id, access_key_id))

        return res.fetchone()[0]

    @connected
    def update_user_keystore(self, conn, cursor, id, keystore):
        cursor.execute("""
        UPDATE users SET keystore = ? WHERE user_id = ?
        """, (keystore, id))

    @connected
    def add_user(self, conn, cursor, username):

        res = cursor.execute("""
        SELECT COUNT(username) FROM users WHERE username = ?
        """, (username,))

        if res.fetchone()[0] > 0:
            raise ValueError("User '{}' already exists".format(username))

        id = b64_hash(username)

        cursor.execute("""
        INSERT INTO users VALUES(?, ?, NULL);
        """, (id, username))

        return (id, username)

    @connected
    def remove_user(self, conn, cursor, username):
        res = cursor.execute("""
        SELECT COUNT(username) FROM users WHERE username = ?
        """, (username,))

        if res.fetchone()[0] == 0:
            raise ValueError("No such user: '{}'".format(username))

        cursor.execute("""
        DELETE FROM users WHERE username = ?
        """, (username,))

    @connected
    def add_access_key(self, conn, cursor, user_id):
        access_key = random_b32_bytes(15)

        expanded_access_key = expand_password(access_key, user_id)
        print("Expanded {} and {} into {}".format(access_key, user_id, expanded_access_key))

        #TODO expire this eventually
        cursor.execute("""
        INSERT INTO active_keys VALUES(?, ?, NULL);
        """, (user_id, expanded_access_key))

        #TODO these should be random and independent for each user (maybe)
        key_id = cursor.lastrowid

        return (access_key, key_id)

    @connected
    def register_device(self, conn, cursor,
                        user_id, device_id, access_key, public_key):
        res = cursor.execute("""
        SELECT COUNT(*) FROM active_keys WHERE
        access_key = ? AND user_id = ?
        """, (access_key, user_id))

        if res.fetchone()[0] == 0:
            raise ValueError("No active access_key '{}' for user '{}'".format(
                access_key, user_id))

        cursor.execute("""
        DELETE FROM active_keys WHERE access_key = ? AND user_id = ?
        """, (access_key, user_id))

        cursor.execute("""
        INSERT INTO devices VALUES(?, ?, NULL, ?)
        """, (user_id, device_id, public_key))

    @connected
    def unregister_device(self, conn, cursor, user_id, device_id):
        cursor.execute("""
        DELETE FROM devices WHERE user_id = ? AND device_id = ?
        """, (user_id, device_id))
