import threading
from selfpass.store import Store
from selfpass.external import run as run_external
from selfpass.management import run as run_management


def test():
    from selfpass.external import encrypt_as_user
    import json
    db = Store("test.db")

    id, access_key = db.get_user_by_name("adam")

    js = {
        "request": "update-keystore",
        "request-nonce": "123"
    }

    print(json.dumps(encrypt_as_user(id, access_key,
                                     json.dumps(js).encode("utf-8"))))


def main():
    db = Store("test.db")
    external = threading.Thread(target=run_external, args=(db,))
    management = threading.Thread(target=run_management, args=(db,))
    external.start()
    management.start()
    # run_external(db)

if __name__ == "__main__":
    main()
