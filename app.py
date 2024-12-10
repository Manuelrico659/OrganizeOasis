from flask import Flask, render_template, url_for, request, redirect, flash, session
from pymongo import MongoClient
from cryptography.fernet import Fernet
import cryptography
import uuid
import os
from dotenv import load_dotenv
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import MySQLdb.cursors
from datetime import timedelta
from authlib.integrations.flask_client import OAuth

# Cargar variables de entorno
load_dotenv(dotenv_path='variables.env')

app = Flask(__name__, template_folder='templates')
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_secret_key")  # Cargar clave secreta desde las variables de entorno
if app.secret_key == "default_secret_key":
    app.logger.warning("Usando clave secreta predeterminada. Esto no es seguro para producción.")
app.permanent_session_lifetime = timedelta(minutes=30)

# Configuración de OAuth
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


@app.route('/authorize/google', endpoint='google_authorize')
def google_authorize():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    # Process user_info or log the user in
    return redirect(url_for('home'))

@app.route('/login/google')
def login_google():
    state = str(uuid.uuid4())
    session['oauth_state'] = state
    redirect_uri = url_for('login_callback', _external=True)
    return google.authorize_redirect(redirect_uri, state=state)

@app.route('/google/callback')
def login_callback():
    try:
        if request.args.get('state') != session.get('oauth_state'):
            raise Exception("State mismatch error!")

        token = google.authorize_access_token()

        session['google_token'] = token

        user_info_response = google.get('https://www.googleapis.com/oauth2/v1/userinfo')
        if user_info_response.status_code != 200:
            raise Exception("Error al obtener información del usuario desde Google.")
        user_info = user_info_response.json()

        # Cifrar el correo del usuario
        encrypted_email = cipher_suite.encrypt(user_info['email'].encode()).decode('utf-8')
        print(f"Encrypted email before storing: {encrypted_email}")

        # Generar una contraseña aleatoria (si es necesario, puedes modificar esto)
        hashed_password = bcrypt.generate_password_hash(str(uuid.uuid4())).decode('utf-8')

        # Guardar usuario en la base de datos SQL
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", [encrypted_email])
        user = cursor.fetchone()

        if not user:
            cursor.execute(""" 
                INSERT INTO users (username, email, firstname, lastname, password) 
                VALUES (%s, %s, %s, %s, %s)
            """, (user_info['email'], encrypted_email, user_info['given_name'], user_info['family_name'], hashed_password))
            mysql.connection.commit()

        cursor.close()

        session['loggedin'] = True
        session['username'] = user_info['email']
        session['email'] = user_info['email']
        session['name'] = user_info['name']
        session['picture'] = user_info.get('picture', '')

        flash('Inicio de sesión con Google exitoso.')
        return redirect(url_for('index'))  # Redirigir al index después del login exitoso

    except Exception as e:
        app.logger.error(f"Error durante la autenticación con Google: {e}")
        flash(f"Error durante la autenticación con Google: {e}")
        return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)