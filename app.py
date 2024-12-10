from flask import Flask, render_template, url_for, request, redirect, flash, session
from pymongo import MongoClient
from cryptography.fernet import Fernet
import cryptography
import uuid
import os
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
import psycopg2
from datetime import timedelta
from authlib.integrations.flask_client import OAuth

# Cargar variables de entorno
load_dotenv(dotenv_path='variables.env')

app = Flask(__name__, template_folder='templates')

# Configuración de la clave secreta (cargar desde variables de entorno)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    raise ValueError("La clave secreta no está definida. Establezca FLASK_SECRET_KEY en las variables de entorno.")


# Configuración de OAuth (Google)
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = os.getenv('GOOGLE_DISCOVERY_URL')
GOOGLE_SCOPES = os.getenv('GOOGLE_SCOPES', 'openid profile email')
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url=GOOGLE_DISCOVERY_URL,
    client_kwargs={'scope': GOOGLE_SCOPES},
    authorize_url='https://accounts.google.com/o/oauth2/auth'
)

# Configuración de MongoDB Atlas (para la lista de tareas)
client = MongoClient(os.getenv('MONGO_URI'))
db = client['todo_database']
todos_collection = db['todos']

# Cargar o generar la clave para cifrado
key_path = "secret.key"
if os.path.exists(key_path):
    with open(key_path, "rb") as key_file:
        key = key_file.read()
else:
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)
cipher_suite = Fernet(key)

# Configuración de PostgreSQL (para registro y login)
app.config['POSTGRES_HOST'] = os.getenv('POSTGRES_HOST')
app.config['POSTGRES_USER'] = os.getenv('POSTGRES_USER')
app.config['POSTGRES_PASSWORD'] = os.getenv('POSTGRES_PASSWORD')
app.config['POSTGRES_DB'] = os.getenv('POSTGRES_DB')

# Inicializando PostgreSQL y Bcrypt
bcrypt = Bcrypt(app)

# Conexión a PostgreSQL
def get_db_connection():
    conn = psycopg2.connect(
        host=os.getenv('POSTGRES_HOST'),
        user=os.getenv('POSTGRES_USER'),
        password=os.getenv('POSTGRES_PASSWORD'),
        dbname=os.getenv('POSTGRES_DB')
    )
    return conn

# ------------- RUTAS PARA REGISTRO Y LOGIN (PostgreSQL) -----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        

        # Prueba con un hash simple
        password = "testpassword"
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Verificación con el mismo hash
        print(bcrypt.check_password_hash(hashed_password, password))  # Debería devolver True


        # Cifrar el correo
        encrypted_email = cipher_suite.encrypt(email.encode()).decode('utf-8')

        # Cifrar la contraseña
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Guardar usuario en la base de datos PostgreSQL
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, email, firstname, lastname, password) 
            VALUES (%s, %s, %s, %s, %s)
        """, (username, encrypted_email, firstname, lastname, hashed_password))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Usuario registrado exitosamente.')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        # Verificar si el usuario existe en la base de datos PostgreSQL
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", [username])
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            # Verificar la contraseña
            if bcrypt.check_password_hash(user[4], password_candidate):  # user[4] is the password column
                session['loggedin'] = True
                session['username'] = username
                
                # Descifrar el correo
                decrypted_email = cipher_suite.decrypt(user[1].encode()).decode('utf-8')  # user[1] is the email column
                session['email'] = decrypted_email
                
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

# ------------- RUTAS PARA LA LISTA DE TAREAS (MongoDB Atlas) -----------------
@app.route("/", methods=["GET", "POST"])
@app.route("/home", methods=["GET", "POST"])
def home():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    user_id = session.get('username')

    if request.method == "POST":
        todo_name = request.form.get("todo_name", "").strip()
        priority = request.form.get("priority")
        todo_date = request.form.get("todo_date")

        if todo_name:
            encrypted_name = cipher_suite.encrypt(todo_name.encode()).decode()
            todos_collection.insert_one({
                'user_id': user_id,
                'id': str(uuid.uuid4()),
                'name': encrypted_name,
                'checked': False,
                'priority': priority,
                'date': todo_date
            })
    
    todos = todos_collection.find({'user_id': user_id})
    items = [
        {
            'id': todo['id'],
            'name': cipher_suite.decrypt(todo['name'].encode()).decode(),
            'checked': todo['checked'],
            'priority': todo['priority'],
            'date': todo['date'],
            'priority_class': f"priority-{todo['priority']}"
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
        todos_collection.update_one(
            {'id': todo_id},
            {'$set': updates}
        )
    
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

        conn = get_db_connection()
        cursor = conn.cursor()
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
        conn.commit()
        cursor.close()
        conn.close()

        flash('Perfil actualizado exitosamente.')

    return render_template('edit_profile.html')

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
