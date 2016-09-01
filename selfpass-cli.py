"""selfpass-cli

Usage:
  selfpass-cli.py user <username> (create|delete|info) [--host=<host>]
  selfpass-cli.py user <username> (add|remove) device [--host=<host>]
  selfpass-cli.py (-h | --help)
  selfpass-cli.py --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --host=<host> The selfpass server host (default: localhost:5000).
"""
from docopt import docopt
import requests
import urllib.parse
import base64
import binascii

def as_url(host, *parts):
    return "http://" + host + "/" + "/".join(p.strip("/") for p in parts)

if __name__ == '__main__':
    args = docopt(__doc__, version='selfpass-cli v0.0.1')

    if args["--host"] is None:
        host = "localhost:5000"
    else:
        host = args["--host"]

    if args["user"]:
        username = args["<username>"]
        if args["create"]:
            response = requests.post(as_url(host, "user", username, "create"))
            json = response.json()
            print("New user with id: {}".format(json["id"]))

        elif args["device"]:
            if args["add"]:
                response = requests.post(as_url(host, "user", username, "add/device"))
                json = response.json()
                print("New device access key: {}".format(json["access_key"]))

        elif args["info"]:
            response = requests.get(as_url(host, "user", username, "info"))
            print(response.json())
