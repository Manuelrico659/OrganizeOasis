from pymongo import MongoClient
import pytest

@pytest.fixture
def mongo_client():
    client = MongoClient('mongodb://localhost:27017/')
    return client

def test_mongo_connection(mongo_client):
    db = mongo_client['todo_database']
    collection = db['todos']
    document = collection.find_one()
    assert document is not None
