from flask import Flask, render_template, url_for, request, redirect, flash, session
from pymongo import MongoClient
from cryptography.fernet import Fernet
import cryptography
import uuid
import os
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import MySQLdb.cursors

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MongoDB connection (para la lista de tareas)
client = MongoClient('mongodb://localhost:27017/')
db = client['todo_database']
todos_collection = db['todos']

# Load or generate a key for encryption and decryption (para cifrar tareas y datos de usuarios)
key_path = "secret.key"
if os.path.exists(key_path):
    with open(key_path, "rb") as key_file:
        key = key_file.read()
else:
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)
cipher_suite = Fernet(key)

# Configuración de MySQL (para registro y login)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'LOGIN_TODOLIST'

# Inicializando MySQL y Bcrypt
mysql = MySQL(app)
bcrypt = Bcrypt(app)

# ------------- RUTAS PARA REGISTRO Y LOGIN (SQL) -----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        print(f"Encryption key: {key}")
        # Cifrar el correo
        encrypted_email = cipher_suite.encrypt(email.encode()).decode('utf-8')
        print(f"Encrypted email before storing: {encrypted_email}")
        
        # Cifrar la contraseña
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Guardar usuario en la base de datos SQL
        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO users (username, email, firstname, lastname, password) 
            VALUES (%s, %s, %s, %s, %s)
        """, (username, encrypted_email, firstname, lastname, hashed_password))
        mysql.connection.commit()
        cursor.close()

        flash('Usuario registrado exitosamente.')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        # Verificar si el usuario existe en la base de datos SQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s", [username])
        user = cursor.fetchone()
        cursor.close()

        if user:
            # Verificar la contraseña
            if bcrypt.check_password_hash(user['password'], password_candidate):
                session['loggedin'] = True
                session['username'] = username
                print(f"Decryption key: {key}")
                # Verificar el correo cifrado antes de descifrar
                print(f"Encrypted email from DB: {user['email']}")
                
                try:
                    # Descifrar el correo
                    decrypted_email = cipher_suite.decrypt(user['email'].encode()).decode('utf-8')
                    session['email'] = decrypted_email
                except cryptography.fernet.InvalidToken:
                    print("Error: InvalidToken al descifrar el correo.")
                    flash('Error al descifrar el correo.')
                    return redirect(url_for('login'))
                
                flash('Inicio de sesión exitoso.')
                return redirect(url_for('home'))
            else:
                flash('Contraseña incorrecta.')
        else:
            flash('Usuario no encontrado.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('username', None)
    session.pop('email', None)
    flash('Has cerrado sesión.')
    return redirect(url_for('login'))

# ------------- RUTAS PARA LA LISTA DE TAREAS (MongoDB) -----------------
@app.route("/", methods=["GET", "POST"])
@app.route("/home", methods=["GET", "POST"])
def home():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    user_id = session.get('username')  # Usar el nombre de usuario o un identificador único

    if request.method == "POST":
        todo_name = request.form.get("todo_name", "").strip()
        priority = request.form.get("priority")
        todo_date = request.form.get("todo_date")  # Obtener la fecha

        if todo_name:
            encrypted_name = cipher_suite.encrypt(todo_name.encode()).decode()
            todos_collection.insert_one({
                'user_id': user_id,
                'id': str(uuid.uuid4()),
                'name': encrypted_name,
                'checked': False,
                'priority': priority,  # Guardar la prioridad de la tarea
                'date': todo_date  # Guardar la fecha de la tarea
            })
    
    todos = todos_collection.find({'user_id': user_id})
    items = [
        {
            'id': todo['id'],
            'name': cipher_suite.decrypt(todo['name'].encode()).decode(),
            'checked': todo['checked'],
            'priority': todo['priority'],  # Pasar la prioridad
            'date': todo['date'],  # Pasar la fecha
            'priority_class': f"priority-{todo['priority']}"  # Asignar clase de prioridad
        } for todo in todos
    ]

    return render_template("index.html", items=items)

@app.route("/edit_todo/<todo_id>", methods=["POST"])
def edit_todo(todo_id):
    new_content = request.form.get('new_text', "").strip()
    new_date = request.form.get('new_date', "").strip()
    
    updates = {}
    
    if new_content:
        encrypted_name = cipher_suite.encrypt(new_content.encode()).decode()
        updates['name'] = encrypted_name
    
    if new_date:
        updates['date'] = new_date
    
    if updates:
        result = todos_collection.update_one(
            {'id': todo_id},
            {'$set': updates}
        )
        if result.modified_count == 0:
            print("No document was updated. Check the todo_id.")
    else:
        print("No new content or date provided.")
    
    return redirect(url_for("home"))



@app.route("/delete_todo/<todo_id>", methods=["POST"])
def delete_todo(todo_id):
    todos_collection.delete_one({'id': todo_id})
    return redirect(url_for("home"))

@app.route("/checked_todo/<todo_id>", methods=["POST"])
def checked_todo(todo_id):
    todo = todos_collection.find_one({'id': todo_id})
    if todo:
        new_checked_status = not todo['checked']
        todos_collection.update_one(
            {'id': todo_id},
            {'$set': {'checked': new_checked_status}}
        )
    return redirect(url_for("home"))

# Página de edición de perfil
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_firstname = request.form['firstname']
        new_lastname = request.form['lastname']
        new_password = request.form['password']

        cursor = mysql.connection.cursor()
        if new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            cursor.execute("""
                UPDATE users
                SET firstname = %s, lastname = %s, password = %s
                WHERE username = %s
            """, (new_firstname, new_lastname, hashed_password, session.get('username')))
        else:
            cursor.execute("""
                UPDATE users
                SET firstname = %s, lastname = %s
                WHERE username = %s
            """, (new_firstname, new_lastname, session.get('username')))
        mysql.connection.commit()
        cursor.close()

        flash('Perfil actualizado exitosamente.')

    return render_template('edit_profile.html')

if __name__ == "__main__":
    app.run(debug=True)
