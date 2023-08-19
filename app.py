from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
jwt = JWTManager(app)

# Simulated user data (replace with a real user database)
users = {
    "user1": "password1",
    "user2": "password2"
}

# Authentication endpoint
# TEST WITH CURL curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1"}' http://localhost:5000/login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users and users[username] == password:
        access_token = create_access_token(identity=username)
        return jsonify({"access_token": access_token}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

# Protected endpoint
#TEST WITH CURL curl -X GET -H "Authorization: Bearer <your-access-token>" http://localhost:5000/protected
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello, {current_user}!"}), 200

if __name__ == '__main__':
    app.run(debug=True)