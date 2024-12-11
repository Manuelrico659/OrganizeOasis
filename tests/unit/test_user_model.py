import pytest
from app import bcrypt
from app import User

def test_password_hashing():
    password = 'password123'
    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    assert bcrypt.check_password_hash(hashed, password)

def test_user_creation():
    user = User(username='testuser', email='testuser@example.com')
    assert user.username == 'testuser'
    assert user.email == 'testuser@example.com'
