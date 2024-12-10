import psycopg2
import pytest

@pytest.fixture
def db_connection():
    conn = psycopg2.connect(
        host='localhost',
        user='postgres_user',
        password='postgres_password',
        dbname='postgres_db'
    )
    return conn

def test_postgres_connection(db_connection):
    cursor = db_connection.cursor()
    cursor.execute("SELECT 1;")
    result = cursor.fetchone()
    assert result == (1,)
    cursor.close()
