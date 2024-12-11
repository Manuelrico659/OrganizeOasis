from flask import Flask, request, jsonify, redirect, url_for
from flask.testing import FlaskClient
import pytest

# Crear la aplicación Flask
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necesario para usar 'flash' y gestionar sesiones

# Simulamos una base de datos en memoria de usuarios y tareas
todos = {}

# Ruta de registro
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    # Aquí podrías agregar validación para evitar duplicados
    # users[username] = password
    return jsonify({'message': 'Usuario registrado exitosamente.'}), 200

# Ruta para crear tareas
@app.route('/home', methods=['POST'])
def create_todo():
    todo_name = request.form['todo_name']
    priority = request.form['priority']
    todo_date = request.form['todo_date']
    
    # Simulación de asignar un ID único para la tarea
    todo_id = str(len(todos) + 1)
    
    todos[todo_id] = {'todo_name': todo_name, 'priority': priority, 'todo_date': todo_date}
    
    return jsonify({'message': 'Task added successfully.'}), 200

# Ruta para eliminar tareas
@app.route('/delete_todo/<todo_id>', methods=['POST'])
def delete_todo(todo_id):
    if todo_id in todos:
        del todos[todo_id]
        return jsonify({'message': 'Task deleted successfully.'}), 200
    else:
        return jsonify({'message': 'Task not found.'}), 404

# Crear el cliente de pruebas para interactuar con la aplicación
@pytest.fixture
def client():
    return app.test_client()

# Prueba de registro y login de usuario
def test_user_registration(client):
    response = client.post('/register', data={'username': 'testuser', 'password': 'securepassword'})
    assert response.status_code == 200
    assert b'Usuario registrado exitosamente.' in response.data

# Prueba para crear una tarea
def test_create_todo(client):
    response = client.post('/home', data={'todo_name': 'Test Task', 'priority': '1', 'todo_date': '2024-12-01'})
    assert response.status_code == 200
    assert b'Task added successfully.' in response.data

# Prueba para eliminar una tarea
def test_delete_todo(client):
    # Crear una tarea antes de intentar eliminarla
    create_response = client.post('/home', data={'todo_name': 'Test Task', 'priority': '1', 'todo_date': '2024-12-01'})
    task_id = '1'  # Basado en la lógica de nuestro ejemplo

    # Intentar eliminar la tarea
    delete_response = client.post(f'/delete_todo/{task_id}')
    assert delete_response.status_code == 200
    assert b'Task deleted successfully.' in delete_response.data
