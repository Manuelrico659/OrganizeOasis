import pytest
from app import cipher_suite
from app.models import Todo # type: ignore

def test_todo_encryption():
    todo_name = 'Test Todo'
    encrypted_name = cipher_suite.encrypt(todo_name.encode()).decode()
    todo = Todo(name=encrypted_name)
    decrypted_name = cipher_suite.decrypt(todo.name.encode()).decode()
    assert decrypted_name == todo_name
