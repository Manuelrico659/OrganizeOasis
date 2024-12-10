from cryptography.fernet import Fernet
import pytest

@pytest.fixture
def cipher():
    key = Fernet.generate_key()
    return Fernet(key)

def test_encryption_decryption(cipher):
    original_data = "Sensitive data"
    encrypted_data = cipher.encrypt(original_data.encode())
    decrypted_data = cipher.decrypt(encrypted_data).decode()
    assert decrypted_data == original_data
