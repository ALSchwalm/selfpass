
#TODO this should probably all still be authenticated
def run(store):
    from flask import Flask, request, jsonify
    from flask_cors import CORS

    management = Flask("selfpass-management")
    CORS(management)

    @management.route("/user/add", methods=["POST"])
    def user_add():
        username = request.get_json()["username"]
        try:
            id, key = store.add_user(username)
        except ValueError:
            return jsonify({
                "error": "User already exists"
            }), 400
        return jsonify({
            "id": id,
            "access_key": key
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
            "access_key": key
        })

    management.run(port=5000)
