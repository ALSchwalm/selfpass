import threading
from selfpass.store import Store
from selfpass.crypto import generate_server_keys
from selfpass.external import run as run_external
from selfpass.management import run as run_management


def main():
    db = Store("test.db")

    # generate initial keys if necessary
    if not db.have_server_keys():
        pub, priv = generate_server_keys()
        db.update_server_keys(pub, priv)

    external = threading.Thread(target=run_external, args=(db,))
    management = threading.Thread(target=run_management, args=(db,))
    external.start()
    management.start()

if __name__ == "__main__":
    main()
