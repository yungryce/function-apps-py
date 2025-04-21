import pytest
from ..helper_functions import validate_json, user_exists  # Import the functions you want to test
    
def test_user_exists(mocker):
    mock_database = mocker.patch('helper_functions.database')  # Mock the database call
    mock_database.return_value = True  # Simulate user exists

    assert user_exists("testuser") is True

def test_validate_json_valid():
    data = {"username": "testuser", "password": "testpass"}
    assert validate_json(data) is True

def test_validate_json_invalid():
    data = {"username": "testuser"}  # Missing password
    assert validate_json(data) is False

def test_user_exists(mocker):
    mock_database = mocker.patch('helper_functions.table_client.get_entity')
    mock_database.return_value = {
        'RowKey': 'testuser',
        'email': 'testuser@example.com',
        'first_name': 'Test',
        'last_name': 'User'
    }

    exists, partition_key, user_data = user_exists("testuser")
    assert exists is True
    assert partition_key == "Users"
    assert user_data == {
        'username': 'testuser',
        'email': 'testuser@example.com',
        'first_name': 'Test',
        'last_name': 'User'
    }