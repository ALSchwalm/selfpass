import sqlite3
import os
from .utils import *
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
        CREATE TABLE users (username TEXT,
                            id TEXT PRIMARY KEY,
                            access_key TEXT,
                            keystore TEXT)
        """)
        conn.commit()

    @connected
    def get_user_by_id(self, conn, cursor, id):
        res = cursor.execute("""
        SELECT username, id, access_key, keystore FROM users WHERE id = ?
        """, (id,))

        if res is None:
            raise ValueError("No user with id: '{}'".format(id))

        return res.fetchone()

    @connected
    def get_user_by_name(self, conn, cursor, username):
        res = cursor.execute("""
        SELECT username, id, access_key, keystore FROM users WHERE username = ?
        """, (username,)).fetchone()

        if res is None:
            raise ValueError("No such user: '{}'".format(username))
        return res

    @connected
    def get_keystore_by_id(self, conn, cursor, id):
        return self.get_user_by_id(id)[3]

    @connected
    def update_user_access_key(self, conn, cursor, id, new_key):
        cursor.execute("""
        UPDATE users SET access_key = ? WHERE id = ?
        """, (new_key, id))

    @connected
    def update_user_keystore(self, conn, cursor, id, keystore):
        cursor.execute("""
        UPDATE users SET keystore = ? WHERE id = ?
        """, (keystore, id))

    @connected
    def add_user(self, conn, cursor, username):

        res = cursor.execute("""
        SELECT COUNT(username) FROM users WHERE username = ?
        """, (username,))

        if res.fetchone()[0] > 0:
            raise ValueError("User '{}' already exists".format(username))

        id = generate_nonce()
        access_key = generate_nonce()

        conn.commit()

        res = cursor.execute("""
        INSERT INTO users VALUES(?, ?, ?, NULL);
        """, (username, id, access_key))

        res = cursor.execute("""
        SELECT id, access_key FROM users WHERE username = ?
        """, (username,))

        return res.fetchone()

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
