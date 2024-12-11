import pytest
from app import cipher_suite, Todo  # Importación directa de `cipher_suite` y `Todo` desde `app.py`

def test_todo_encryption():
    todo_name = 'Test Todo'
    encrypted_name = cipher_suite.encrypt(todo_name.encode()).decode()
    todo = Todo(name=encrypted_name)
    decrypted_name = todo.decrypt_name()
    assert decrypted_name == todo_name
