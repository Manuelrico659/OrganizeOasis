import pytest
from flask import Flask
from flask.testing import FlaskClient

@pytest.fixture
def app() -> Flask:
    app = Flask(__name__)
    # Configuración adicional del app
    return app

@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()

def test_login(client):
    response = client.post('/login', data={'username': 'test_user', 'password': 'password123'})
    assert response.status_code == 200
    assert 'Inicio de sesión exitoso.' in response.data
