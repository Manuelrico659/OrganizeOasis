from flask import Flask
import pytest
from flask.testing import FlaskClient

@pytest.fixture
def client():
    app = Flask(__name__)
    # Configuración adicional
    return app.test_client()

def test_register(client):
    response = client.post('/register', data={'firstname': 'John', 'lastname': 'Doe', 'email': 'john.doe@example.com', 'username': 'johndoe', 'password': 'securepassword'})
    assert response.status_code == 302  # Redirección al login
    assert b'Usuario registrado exitosamente.' in response.data

