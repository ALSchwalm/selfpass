




# would actually be a database query
users = [User("adam")]





def generate_request(user, method, request_nonce=None):
    request = {
        "request": method,
        "request-nonce": request_nonce if request_nonce else generate_nonce(),
    }

    return json.dumps(encrypt_as_user(user, json.dumps(request).encode("utf-8")))





#tests
request = generate_request(users[0], method="retrieve-keystore")
handle_request(request)
