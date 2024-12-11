from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    # Aquí va tu lógica de validación del usuario
    username = request.form['username']
    password = request.form['password']
    
    if username == 'test_user' and password == 'password123':
        return jsonify(message="Inicio de sesión exitoso."), 200
    return jsonify(message="Credenciales inválidas."), 401

if __name__ == '__main__':
    app.run(debug=True)
