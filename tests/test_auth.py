import pytest
from app import app  # Import the Flask app for testing

@pytest.fixture
def client():
    # Set up the app for testing
    app.config['TESTING'] = True
    # Create a test client to make requests to the app
    with app.test_client() as client:
        yield client  # Provide the client for use in tests

def test_successful_login(client):
    # Test logging in with correct credentials
    response = client.post('/login', data={
        'username': 'validUser',  # Valid username
        'password': 'validPassword1'  # Valid password
    })
    with client:
        # Check that the user is logged in
        assert session['loggedin'] == True
        # Check that the username in the session is correct
        assert session['username'] == 'validUser'
        # Check that the response redirects (status code 302)
        assert response.status_code == 302

def test_login_with_invalid_credentials(client):
    # Test logging in with incorrect credentials
    response = client.post('/login', data={
        'username': 'invalidUser',  # Incorrect username
        'password': 'wrongPassword'  # Incorrect password
    })
    # Check that the error message "Usuario no encontrado." is present
    assert b'Usuario no encontrado.' in response.data
    # Check that the user is not logged in
    assert session.get('loggedin') is None
