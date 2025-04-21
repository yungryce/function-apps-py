import os
import hashlib
import re
import logging
import random
import string
from datetime import datetime, timedelta
from azure.data.tables import TableServiceClient
from azure.core.exceptions import ResourceNotFoundError


# Use AzureWebJobsStorage connection string from environment variables
connection_string = os.getenv("AzureWebJobsStorage")

# Connect to the Azure Table Storage
table_service = TableServiceClient.from_connection_string(conn_str=connection_string)
user_table_client = table_service.get_table_client(table_name="Users")

def validate_json(data, *fields):
    """Validate if required fields are present in the request JSON."""
    for field in fields:
        if field not in data:
            return {"error": f"Missing field {field}"}, 400
    return None

def hash_password(password):
    """Hash the password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def is_valid_email(email):
    """Validate the email format using a regular expression."""
    email_regex = r'^[a-zA-Z0-9_.+-]{3,}@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

def user_exists(username: str, email: str = None):
    """
    Check if a user exists in the 'Users' table by their username (RowKey) and email.
    If the user exists, fetch and return the PartitionKey along with the user data.

    Args:
        username (str): The username of the user to check.
        email (str): The email of the user to check. (optional)

    Returns:
        tuple: (True, PartitionKey, user_data) if the user exists, 
               (False, None, None) otherwise.
    """

    try:
        # Query the Users table for the specified username and email
        if email:
            query_filter = f"RowKey eq '{username}' or email eq '{email}'"
        else:
            query_filter = f"RowKey eq '{username}'"
        user_entities = user_table_client.query_entities(query_filter)

        # If the user exists, prepare user data and return
        for user_entity in user_entities:
            if user_entity['is_deleted']:
                return False, None, None
            user_data = {
                'username': user_entity['RowKey'],  # assuming RowKey is username
                'email': user_entity['email'],
                'first_name': user_entity['first_name'],
                'last_name': user_entity['last_name'],
                # Password should not be returned for security reasons
            }
            return True, user_entity['PartitionKey'], user_data

        # If no user is found, return False and None
        return False, None, None

    except Exception as e:
        # For any exception, raise it
        raise e
    

async def update_user_ip(username: str, ip_address: str):
    """
    Update the user's IP address in the Users table.

    This function retrieves the user's current IP address list, ensures it contains only the last 4 IP addresses,
    appends a new IP address, and keeps the total number of IP addresses to 5.

    Args:
        username (str): The username of the user.
        ip_address (str): The new IP address to be added.
    """

    try:
        user_entity = user_table_client.get_entity(partition_key=username, row_key=username)

        # Ensure the ip_address field is a list
        if 'ip_address' not in user_entity:
            user_entity['ip_address'] = []

        # If the IP address is not already in the list, append it
        if ip_address not in user_entity['ip_address']:
            # Keep only the last 4 IP addresses in the list
            user_entity['ip_address'].append(ip_address)

            # Ensure the total number of IP addresses does not exceed 5
            if len(user_entity['ip_address']) > 5:
                user_entity['ip_address'] = user_entity['ip_address'][-5:]

            user_table_client.update_entity(entity=user_entity)
            logging.info(f"Updated IP address for user {username}: {ip_address}")
        else:
            logging.info(f"IP address {ip_address} already exists for user {username}.")

    except ResourceNotFoundError:
        logging.warning(f"User {username} not found in the Users table.")
    except Exception as e:
        logging.error(f"Error updating IP address for user {username}: {str(e)}")



async def ip_checker(username: str, ip_address: str):
    """
    Check if the provided IP address is in the user's list of allowed IP addresses.

    Args:
        username (str): The username of the user.
        ip_address (str): The IP address to check.

    Returns:
        bool: True if the IP address is allowed, False otherwise.
    """
    user_client = table_service.get_table_client(table_name="Users")

    try:
        user_entity = user_client.get_entity(partition_key=username, row_key=username)
        
        # Ensure the ip_address field is a list
        if 'ip_address' in user_entity:
            return ip_address in user_entity['ip_address']
        else:
            return False  # No IP addresses are stored for the user

    except ResourceNotFoundError:
        logging.warning(f"User {username} not found in the Users table.")
        return False
    except Exception as e:
        logging.error(f"Error checking IP address for user {username}: {str(e)}")
        return False

    
        
def check_password(username: str, user_input_password: str):
    """
    Check if the provided password matches the stored password hash
    for the specified user.

    Args:
        username (str): The username to query in the storage.
        user_input_password (str): The plain text password provided by the user.

    Returns:
        bool: True if the passwords match, False otherwise.
    """
    try:
        # Query the Users table for the specified username
        query_filter = f"RowKey eq '{username}'"
        user_entities = user_table_client.query_entities(query_filter)

        # Fetch the first matching user entity
        user_entity = next(user_entities, None)

        if user_entity:
            # Fetch the stored password hash from the user entity and Compare the stored hash with the hash of the user input password
            stored_password_hash = user_entity['password']
            return stored_password_hash == hash_password(user_input_password)

    except Exception as e:
        # Handle exceptions (e.g., user not found)
        if "ResourceNotFound" in str(e):
            return False  # User does not exist
        else:
            # For any other exception, raise it
            raise e


def validate_password(password: str) -> bool:
    """
    Validate the strength of a password based on defined criteria.

    Args:
        password (str): The password to validate.

    Returns:
        bool: True if the password is strong, False otherwise.
    """
    # Check password length
    if len(password) < 8:
        return False

    # Check for uppercase letters
    if not re.search(r'[A-Z]', password):
        return False

    # Check for lowercase letters
    if not re.search(r'[a-z]', password):
        return False

    # Check for digits
    if not re.search(r'[0-9]', password):
        return False

    # Check for special characters
    if not re.search(r'[@$!%*?&]', password):
        return False

    # Optionally check against a list of common passwords
    common_passwords = [
        "password", "123456", "12345678", "qwerty", "abc123", 
        "letmein", "welcome", "admin", "user", "passw0rd"
    ]
    if password in common_passwords:
        return False

    return True


def generate_confirmation_token(length=6, expires_in=1):
    """
    Generates a random confirmation token.

    The token consists of uppercase letters, lowercase letters, digits, 
    and allowed special characters.

    Args:
        length (int): The length of the token to be generated. Default is 6.

    Returns:
        str: A randomly generated token of the specified length.
    """
    # Define the character pool for the token
    allowed_characters = string.ascii_uppercase + string.ascii_lowercase + string.digits + "!@#$%^&*"
    
    # Randomly select characters from the allowed pool
    token = ''.join(random.choice(allowed_characters) for _ in range(length))

    # Set expiration time (current time + expires_in hours)
    expiration_time = datetime.utcnow() + timedelta(hours=expires_in)
    
    return token, expiration_time.isoformat()


async def confirm_email(username: str) -> bool:
    """
    Check if the user's email is confirmed.

    Args:
        username (str): The username of the user.

    Returns:
        bool: True if the email is confirmed, False otherwise.
    """
    try:
        # Fetch user from the Users table
        user_entity = user_table_client.get_entity(partition_key=username, row_key=username)
        
        # Check if the confirm_email field exists and is True
        return user_entity.get('confirm_email', False)

    except ResourceNotFoundError:
        logging.warning(f"User {username} not found in the Users table.")
        return False
    except Exception as e:
        logging.error(f"Error checking confirm_email for user {username}: {str(e)}")
        return False
