from flask import Flask, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necesario para usar 'flash' para mensajes

@app.route('/register', methods=['POST'])
def register():
    firstname = request.form['firstname']
    lastname = request.form['lastname']
    email = request.form['email']
    username = request.form['username']
    password = request.form['password']
    
    # Aquí iría la lógica para guardar al usuario, como validaciones y almacenamiento en la base de datos.
    # Vamos a simular un registro exitoso.

    flash("Usuario registrado exitosamente.")  # Mensaje de éxito
    return redirect(url_for('login'))  # Redirigir al login, como en tu prueba.

@app.route('/login')
def login():
    return 'Login Page'

if __name__ == '__main__':
    app.run(debug=True)
