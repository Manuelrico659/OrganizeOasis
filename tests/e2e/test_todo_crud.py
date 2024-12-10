from flask import Flask
import pytest
from flask.testing import FlaskClient

@pytest.fixture
def client():
    app = Flask(__name__)
    # Configuración adicional
    return app.test_client()

def test_create_todo(client):
    response = client.post('/home', data={'todo_name': 'Test Task', 'priority': '1', 'todo_date': '2024-12-01'})
    assert response.status_code == 200
    assert b'Task added successfully.' in response.data

def test_delete_todo(client):
    response = client.post('/delete_todo/testtodoid')
    assert response.status_code == 200
    assert b'Task deleted successfully.' in response.data

