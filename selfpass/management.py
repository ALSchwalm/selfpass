
#TODO this should probably all still be authenticated
def run(store):
    from flask import Flask, request, jsonify
    from flask_cors import CORS
    from .utils import format_access_key

    management = Flask("selfpass-management")
    CORS(management)

    @management.route("/user/<username>/create", methods=["POST"])
    def user_add(username):
        try:
            id, username = store.add_user(username)
        except ValueError as e:
            return jsonify({
                "error": "User already exists"
            }), 400
        return jsonify({
            "id": id,
            "username": username
        })

    @management.route("/user/<username>/add/device", methods=["POST"])
    def device_add(username):
        try:
            _, id, _ = store.get_user_by_name(username)
            access_key, key_id = store.add_access_key(id)
        except Exception as e:
            print(e)
            return "", 400
        return jsonify({
            "access_key": format_access_key(access_key, key_id),
        })

    @management.route("/user/<username>/info", methods=["GET"])
    def user_info(username):
        try:
            _, id, key, _ = store.get_user_by_name(username)
        except ValueError:
            return jsonify({
                "error": "No such user"
            }), 400
        return jsonify({
            "id": id,
            "access_key": format_access_key(key),
            "username": username
        })

    management.run(port=5000)
