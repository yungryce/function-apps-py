import os
import json
import logging
import base64
import datetime
import jwt
from guard import authenticate
from helper_functions import validate_json, user_exists, check_password, validate_password, table_service, is_valid_email, hash_password, update_user_ip, generate_confirmation_token, confirm_email
from rate_limit import is_rate_limited, is_ip_rate_limited
import azure.functions as func
from queue_triggers import bp
from active_cron_trigger import cp
from azure.storage.queue import QueueServiceClient


# Create the QueueServiceClient and Define the queue client for your specific queue
ACTION_QUEUE = "user-action-queue"
SECRET_KEY = os.getenv("SECRET_KEY")

connection_string = os.getenv("AzureWebJobsStorage")
email_storage_connection_string = os.getenv('EMAIL_STORAGE_CONNECTION_STRING')
user_client = table_service.get_table_client(table_name="Users")
queue_service_client = QueueServiceClient.from_connection_string(conn_str=connection_string)
queue_service_client_email = QueueServiceClient.from_connection_string(email_storage_connection_string)
email_queue_client = queue_service_client_email.get_queue_client("emailqueue")

# Initialize the function app
app = func.FunctionApp()
app.register_functions(bp) 
app.register_functions(cp)

@app.function_name(name="register")
@app.route(route="register", methods=["POST"])
async def register(req: func.HttpRequest) -> func.HttpResponse:
    """
    Register a new user by sending data to the queue for processing.

    This function validates input JSON data for user registration,
    checks for existing users, and if validation passes,
    it sends the user data to the user registration queue.

    Args:
        req (func.HttpRequest): The incoming HTTP request containing user data.

    Returns:
        func.HttpResponse: A JSON response indicating the result of the operation.
                           - 202 Accepted if registration is in process.
                           - 409 Conflict if the username or email already exists.
                           - 400 Bad Request if validation fails.
                           - 500 Internal Server Error if sending to the queue fails.
    """
    logging.info("Registering a new user.")
    
    # Parse input data
    data = req.get_json()

    # Validate input JSON
    error = validate_json(data, 'username', 'email', 'password', 'first_name', 'last_name')
    if error:
        logging.warning("Validation error: %s", error)
        return func.HttpResponse(json.dumps(error), status_code=error[1])
    
    username = data['username']
    email = data['email']

    # Validate email format
    if not is_valid_email(email):
        logging.warning("Invalid email format: %s", email)
        return func.HttpResponse(
            json.dumps({"error": "Invalid email format"}),
            status_code=400
        )

    # Check rate limiting for both username and email
    identifiers = [username, email]
    for identifier in identifiers:
        if is_rate_limited(identifier):
            return func.HttpResponse(
                json.dumps({'error': 'Too many requests. Please try again later.'}),
                status_code=429  # Too Many Requests
            )

    # Check IP rate limiting
    user_ip = req.headers.get("X-Forwarded-For", req.headers.get("REMOTE_ADDR", "unknown"))
    if is_ip_rate_limited(user_ip):
        return func.HttpResponse(
            json.dumps({'error': 'Too many requests from this IP. Please try again later.'}),
            status_code=429  # Too Many Requests
        )

    # Check if the user exists and prepare user data
    user_exists_result, partition_key, user_data = user_exists(username, email)
    if user_exists_result:
        logging.warning("User  already exists: %s", username)
        return func.HttpResponse(
            json.dumps({"error": "Username or Email already exists"}), 
            status_code=409
        )

    # Validate password
    if not validate_password(data['password']):
        logging.warning("Password does not meet requirements")
        return func.HttpResponse(
            json.dumps({"error": "Password does not meet requirements"}),
            status_code=400
        )
    
    # Prepare user_data with values from the request
    email_token, token_expires_at = generate_confirmation_token()

    user_data = {
        'username': username,
        'email': email,
        'first_name': data['first_name'],
        'last_name': data['last_name'],
        'password': hash_password(data['password']),
        'ip_address': [user_ip],  # Store the IP address as a list
        'email_token': email_token,
        'token_expires_at': token_expires_at,
        'action': 'signup'
    }
    
    # Send user data to the queue
    try:
        queue_client = queue_service_client.get_queue_client(ACTION_QUEUE)
        encoded_message = base64.b64encode(json.dumps(user_data).encode('utf-8')).decode('utf-8')
        queue_client.send_message(encoded_message)
        logging.info("User registration data sent to queue: %s", user_data)
        
        user_data.pop('password', None)
        encoded_email = base64.b64encode(json.dumps(user_data).encode('utf-8')).decode('utf-8')
        email_queue_client.send_message(encoded_email)
        logging.info(f"Email queue message sent for {username} registration to email function app storage.")

        return func.HttpResponse(json.dumps({"message": "User registration successful"}), status_code=202)
    except Exception as e:
        logging.error("Failed to send message to the action queue or email queue: %s", str(e))
        return func.HttpResponse(
            json.dumps({"error": "Failed to process the registration", "message": str(e)}),
            status_code=500
        )


# implement rate limiting for login function
@app.function_name(name="login")
@app.route(route="login", methods=["POST"])
async def login(req: func.HttpRequest) -> func.HttpResponse:
    """
    User login function for Azure Table Storage.

    This function validates the username and password provided in the login request.
    If valid, it generates a JWT token, sends a login success message to the login queue, 
    and returns the token in the Authorization header.
    If invalid, it returns an error message.

    Args:
        req (func.HttpRequest): The incoming HTTP request containing username and password.

    Returns:
        func.HttpResponse: A JSON response indicating the result of the login attempt.
                           - 200 OK if login is successful, with JWT token in the headers.
                           - 401 Unauthorized if the username or password is invalid.
                           - 400 Bad Request if validation fails.
    """
    logging.info("User login attempt.")
    
    try:
        # Parse input data
        data = req.get_json()

        # Validate input JSON
        error = validate_json(data, 'username', 'password')
        if error:
            logging.warning("Validation error: %s", error)
            return func.HttpResponse(json.dumps(error), status_code=error[1])
        
        username = data['username']
        password = data['password']
        
        # Capture user's IP address
        ip_address = req.headers.get('X-Forwarded-For', req.headers.get('Remote-Addr', 'Unknown IP'))

        # Check rate limiting for both username and email
        if is_rate_limited(username):
            return func.HttpResponse(
                json.dumps({'error': 'Too many requests. Please try again later.'}),
                status_code=429  # Too Many Requests
            )

        # Check IP rate limiting
        user_ip = req.headers.get("X-Forwarded-For", req.headers.get("REMOTE_ADDR", "unknown"))
        if is_ip_rate_limited(user_ip):
            return func.HttpResponse(
                json.dumps({'error': 'Too many requests from this IP. Please try again later.'}),
                status_code=429  # Too Many Requests
            )
        
        # Check if the user exists and validate the password
        exists, partition_key, user_data = user_exists(username)

        if exists and check_password(username, password):
            logging.info("Login successful for user: %s", username)

            # Check if the user's email is confirmed
            if not await confirm_email(username):
                return func.HttpResponse(
                    json.dumps({"error": "Email not confirmed. Please verify your email."}),
                    status_code=401
                )
            
            # Update the user's IP address
            await update_user_ip(username, ip_address)
            
            # Check if the user has an active token in the Blacklist table
            try:

                blacklist_client = table_service.get_table_client(table_name="Blacklist")
                active_tokens = blacklist_client.query_entities(
                    query_filter=f"PartitionKey eq '{username}' and active eq true".format(username)
                )
                active_token = next(active_tokens, None)
                if active_token:
                    logging.info(f"User  {username} has an active token: {active_token['RowKey']}")
                    token = active_token['RowKey']
                else:
                    # Generate a new JWT token
                    payload = {
                        'sub': username,  # Subject: the username
                        'iat': datetime.datetime.utcnow(),  # Issued at
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Expiration time
                    }
                    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                    logging.info(f"Generated JWT token for user: {username}")
            except Exception as e:
                logging.error(f"Error checking for active token: {str(e)}")
                return func.HttpResponse(
                    json.dumps({"error": "Internal server error", "message": str(e)}),
                    status_code=500
                )

            # Create a dictionary with the necessary data to pass to the queue
            queue_data = {
                'username': username,
                'active': True,
                'token': token,
                'action':  'login'
            }

            # Send the queue data to the login queue
            queue_client = queue_service_client.get_queue_client(ACTION_QUEUE)
            encoded_message = base64.b64encode(json.dumps(queue_data).encode('utf-8')).decode('utf-8')
            queue_client.send_message(encoded_message)

            user_data['action'] = 'login'
            user_data['login_ip'] = ip_address
            user_data['login_time'] = datetime.datetime.utcnow().strftime('%B %d, %Y %H:%M:%S')
            encoded_email = base64.b64encode(json.dumps(user_data).encode('utf-8')).decode('utf-8')
            email_queue_client.send_message(encoded_email)
            logging.info(f"Email queue message sent for {username} registration to email function app storage.")

            # Include the token in the response headers
            headers = {
                'Authorization': f'Bearer {token}'  # Adding Authorization header
            }
            return func.HttpResponse(
                json.dumps({"message": "Login successful.", "user_data": user_data}),
                status_code=200,
                headers=headers  # Include the headers
            )
        else:
            logging.warning("Invalid login attempt for user: %s", username)
            return func.HttpResponse(json.dumps({"error": "Invalid username or password."}), status_code=401)
    except Exception as e:
        logging.error(f"Exception during login for user '{username}': {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Internal server error", "message": str(e)}),
            status_code=500
        )
    

@app.function_name(name="logout")
@app.route(route="logout", methods=["POST"])
@authenticate
async def logout(req: func.HttpRequest) -> func.HttpResponse:
    """
    User logout function for Azure Table Storage.

    This function receives a token, and sends the logout data to a queue for processing.

    Args:
        req (func.HttpRequest): The incoming HTTP request containing the token.

    Returns:
        func.HttpResponse: A JSON response indicating the result of the logout attempt.
                           - 200 OK if logout is successful.
                           - 400 Bad Request if validation fails.
    """
    try:

        # Fetch authenticated data from the request
        current_user = req.user
        token = req.token
        username = current_user['username']

        # Prepare data to send to the logout queue
        logout_data = {
            'username': username,
            'token': token,
            'action': 'logout',
            'active':  False
        }

        # Send the logout data to the logout queue
        queue_client = queue_service_client.get_queue_client(ACTION_QUEUE)  # Define your logout queue name
        encoded_message = base64.b64encode(json.dumps(logout_data).encode('utf-8')).decode('utf-8')
        queue_client.send_message(encoded_message)

        # Prepare and send data to the email queue
        logout_data.pop('token', None)  # Exclude sensitive data
        logout_data.update({
            'first_name': current_user['first_name'],
            'last_name': current_user['last_name'],
            'email': current_user['email'],
            'logout_ip': req.headers.get("X-Forwarded-For", req.headers.get("REMOTE_ADDR", "unknown")),
            'logout_time': datetime.datetime.utcnow().strftime('%B %d, %Y %H:%M:%S')
        })
        encoded_email = base64.b64encode(json.dumps(logout_data).encode('utf-8')).decode('utf-8')
        email_queue_client.send_message(encoded_email)
        logging.info(f"Email queue message sent for {username} registration to email function app storage.")

        return func.HttpResponse(json.dumps({"message": "Logout successful."}), status_code=200)
    except Exception as e:
        logging.error(f"Exception during logout: {str(e)}")
        return func.HttpResponse(json.dumps({"error": "Internal server error", "message": str(e)}), status_code=500)


@app.function_name(name="get_user")
@app.route(route="get_user/{username}", methods=["GET"])
async def get_user(req: func.HttpRequest) -> func.HttpResponse:
    """
    Retrieve user data if the user exists in the table.

    This function checks if the specified user exists in the Azure Table Storage.
    If the user is found, it returns the user's data along with the PartitionKey.
    If not, it returns a message indicating that the user was not found.

    Args:
        req (func.HttpRequest): The incoming HTTP request containing the username.

    Returns:
        func.HttpResponse: A JSON response with user data or a message indicating
                           the user was not found.
                           - 200 OK with user data if found.
                           - 404 Not Found if the user does not exist.
    """
    
    username = req.route_params.get("username")
    logging.info("Fetching user data for username: %s", username)
    
    # Check if the user exists and fetch user data
    exists, partition_key, user_data = user_exists(username)

    if exists and not user_data.get('is_deleted'):
        logging.info("User found: %s", username)
        # Return the user data along with the PartitionKey
        response = {
            "exists": True,
            "partition_key": partition_key,
            "user_data": user_data
        }
        return func.HttpResponse(json.dumps(response), status_code=200)
    else:
        logging.warning("User not found or deleted: %s", username)
        # Return a message indicating the user was not found or deleted
        response = {"exists": False, "message": "User not found or deleted"}
        return func.HttpResponse(json.dumps(response), status_code=404)
    

@app.function_name(name="get_all_users")
@app.route(route="users", methods=["GET"])
async def get_all_users(req: func.HttpRequest) -> func.HttpResponse:
    """
    Get all users stored in the Azure Table Storage.

    This function retrieves all user entities from the 'Users' table 
    and returns them as a JSON response.

    Args:
        req (func.HttpRequest): The incoming HTTP GET request.

    Returns:
        func.HttpResponse: A JSON response containing all users' data.
                           - 200 OK if users are successfully retrieved.
                           - 500 Internal Server Error if an error occurs.
    """
    logging.info("Retrieving all users.")

    try:
        # Query all entities in the 'Users' table
        users = []
        entities = user_client.list_entities()
        
        # Iterate through each entity and append to the list
        for entity in entities:
            if entity.get('is_deleted'):
                continue
            
            user_data = {
                'username': entity['RowKey'],  # Assuming RowKey is username
                'email': entity['email'],
                'first_name': entity['first_name'],
                'last_name': entity['last_name']
                # Add more fields as needed, but avoid returning sensitive data like passwords
            }
            users.append(user_data)

        logging.info(f"Total users retrieved: {len(users)}")
        
        # Return the list of users as a JSON response
        return func.HttpResponse(
            json.dumps({"users": users}),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error retrieving users: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Failed to retrieve users", "message": str(e)}),
            status_code=500
        )


@app.function_name(name="delete_user")
@app.route(route="delete_user", methods=["DELETE"])
@authenticate
async def delete_user(req: func.HttpRequest) -> func.HttpResponse:
    """
    Mark a user as deleted in the Azure Table Storage and remove them from the blacklist.

    This function checks if the specified user exists in the Azure Table Storage.
    If the user is found, it updates the user's data to mark them as deleted and deletes
    all occurrences of the user in the blacklist table, then returns a success message.
    If not, it returns a message indicating that the user was not found.

    Args:
        req (func.HttpRequest): The incoming HTTP request containing the username.

    Returns:
        func.HttpResponse: A JSON response indicating the result of the deletion attempt.
                           - 200 OK if the user was successfully marked as deleted.
                           - 404 Not Found if the user does not exist.
                           - 500 Internal Server Error if an error occurs during deletion.
    """
    
    # Fetch authenticated data from the request
    current_user = req.user
    username = current_user['username']
    logging.info(f"Attempting to delete user: %s", username)

    user_data = {
        'username': username,   
        'action': 'delete_user'
    }
    
    try:
        # Send delete operation to the queue
        encoded_message = base64.b64encode(json.dumps(user_data).encode('utf-8')).decode('utf-8')
        queue_client = queue_service_client.get_queue_client(ACTION_QUEUE)
        queue_client.send_message(encoded_message)
        logging.info("User deletion message sent to queue for: %s", username)
        
        # Prepare and send data to the email queue
        user_data.update({
            'first_name': current_user['first_name'],
            'last_name': current_user['last_name'],
            'email': current_user['email'],
            'deletion_time': datetime.datetime.utcnow().strftime('%B %d, %Y %H:%M:%S')
        })
        encoded_email = base64.b64encode(json.dumps(user_data).encode('utf-8')).decode('utf-8')
        email_queue_client.send_message(encoded_email)
        logging.info(f"Email queue message sent for {username} deletion to email function app storage.")
        
        return func.HttpResponse(json.dumps({"message": "User marked as deleted successfully."}), status_code=200)
    except Exception as e:
        logging.error(f"Error marking user '{username}' as deleted: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Failed to mark user as deleted", "message": str(e)}),
            status_code=500
        )


@app.function_name(name="verify_email")
@app.route(route="verify_email/{username}", methods=["POST"])
async def verify_email(req: func.HttpRequest) -> func.HttpResponse:
    """
    Confirm the user's email address by validating the provided email token.

    This function retrieves the email token sent to the user's email and, if valid, sets the 'confirm_email' field to True in the Users table.

    Args:
        req (func.HttpRequest): The incoming HTTP request containing the email token.

    Returns:
        func.HttpResponse: A JSON response indicating success or failure of email confirmation.
    """
    try:
        # Parse request data
        username = req.route_params.get('username')
        data = req.get_json()

        # Validate the presence of the email_token in the request body
        error = validate_json(data, 'email_token')
        if error:
            return func.HttpResponse(json.dumps({"error": "Missing or invalid email_token"}), status_code=400)

        email_token = data['email_token']
        
        # Find the user associated with the provided email_token
        try:
            # Query to find user by the email_token
            query_filter = f"PartitionKey eq '{username}' and email_token eq '{email_token}'"
            user_entities = user_client.query_entities(query_filter=query_filter)
            
            # Check if any user entity is found
            user_entity = next(user_entities, None)
            if not user_entity:
                return func.HttpResponse(
                    json.dumps({"error": "Invalid Token. Please request a new token."}),
                    status_code=400
                )

            # Check if token has expired
            token_expires_at = user_entity.get('token_expires_at')
            if token_expires_at:
                expiration_time = datetime.datetime.fromisoformat(token_expires_at)
                current_time = datetime.datetime.utcnow()

                if current_time > expiration_time:
                    return func.HttpResponse(
                        json.dumps({"error": "Token has expired."}),
                        status_code=400
                    )
            
            # Check if email is already confirmed
            if user_entity.get('confirm_email', False):
                return func.HttpResponse(
                    json.dumps({"message": "Email is already confirmed."}),
                    status_code=200
                )
            
            # Set the confirm_email field to True
            user_entity['confirm_email'] = True

            # Update the user entity in the Users table
            user_client.update_entity(entity=user_entity)
            logging.info(f"Email confirmation successful for user: {user_entity['RowKey']}")

            # Prepare and send data to the email queue
            user_data = {
                'action': 'confirm_email',
                'username': user_entity['RowKey'],
                'email': user_entity['email'],
                'first_name': user_entity['first_name'],
                'last_name': user_entity['last_name'],
            }
            encoded_email = base64.b64encode(json.dumps(user_data).encode('utf-8')).decode('utf-8')
            email_queue_client.send_message(encoded_email)
            logging.info(f"Email queue message sent for {username} email verification")

            return func.HttpResponse(
                json.dumps({"message": "Email confirmed successfully."}),
                status_code=200
            )
        
        except StopIteration:
            # No matching entity found
            return func.HttpResponse(
                json.dumps({"error": "Invalid email token."}),
                status_code=400
            )
        except Exception as e:
            logging.error(f"Error confirming email: {str(e)}")
            return func.HttpResponse(
                json.dumps({"error": "Internal server error", "message": str(e)}),
                status_code=500
            )

    except Exception as e:
        logging.error(f"Error processing email confirmation request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Internal server error", "message": str(e)}),
            status_code=500
        )
        

@app.function_name(name="forgot_password")
@app.route(route="forgot_password", methods=["POST"])
async def forgot_password(req: func.HttpRequest) -> func.HttpResponse:
    """
    Forgot password HTTP trigger that generates a password reset token.
    Updates the email_token field in the Users table and sets confirm_email to False.
    
    Args:
        req (func.HttpRequest): The incoming HTTP request containing the email.
    
    Returns:
        func.HttpResponse: A JSON response indicating the result of the token generation.
    """
    try:
        # Parse request body
        data = req.get_json()

        # Validate the input JSON (should contain 'email')
        error = validate_json(data, 'email')
        if error:
            logging.warning("Validation error: %s", error)
            return func.HttpResponse(json.dumps(error), status_code=error[1])

        email = data['email']
        
        # Check if the user exists using email (or username if desired)
        user_exists_flag, partition_key, user_data = user_exists(username=None, email=email)
        
        if not user_exists_flag:
            logging.warning(f"User with email '{email}' not found.")
            return func.HttpResponse(
                json.dumps({"error": "User not found with the provided email."}),
                status_code=404
            )

        # Generate the confirmation token
        email_token, token_expires_at = generate_confirmation_token()

        # Update the user entity: set email_token and confirm_email to False
        query_filter = f"email eq '{email}'"
        user_entities = user_client.query_entities(query_filter=query_filter)
        user_entity = next(user_entities, None)

        if user_entity:
            user_entity['email_token'] = email_token
            user_entity['confirm_email'] = False

            user_client.update_entity(entity=user_entity)
            logging.info(f"Password reset token generated for email: {email}")
            
            # Create a queue message to send an email
            message = {
                "action": "forgot_password",
                "email": email,
                "email_token": email_token,
                "token_expires_at": token_expires_at
            }
            
            encoded_email = base64.b64encode(json.dumps(message).encode('utf-8')).decode('utf-8')
            email_queue_client.send_message(encoded_email)
            logging.info(f"Password reset token generated and email sent for {email}")

            # Send response (you may want to trigger an email sending function here)
            return func.HttpResponse(
                json.dumps({"message": "Password reset token generated. Please check your email."}),
                status_code=200
            )
        else:
            return func.HttpResponse(
                json.dumps({"error": "User entity not found after lookup."}),
                status_code=404
            )

    except Exception as e:
        logging.error(f"Error generating password reset token for email '{email}': {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Internal server error", "message": str(e)}),
            status_code=500
        )



@app.function_name(name="change_password")
@app.route(route="change_password", methods=["POST"])
async def change_password(req: func.HttpRequest) -> func.HttpResponse:
    """
    Change user password function for Azure Table Storage.

    This function verifies the old password, and if valid, updates the user's password to a new one.

    Args:
        req (func.HttpRequest): The incoming HTTP request containing old and new passwords.

    Returns:
        func.HttpResponse: A JSON response indicating the result of the password change attempt.
                           - 200 OK if password is successfully changed.
                           - 401 Unauthorized if the old password is incorrect.
                           - 400 Bad Request if validation fails.
    """
    logging.info("User password change attempt.")
    
    try:
        # Parse input data
        data = req.get_json()

        # Validate input JSON
        error = validate_json(data, 'username', 'new_password', 'email_token')
        if error:
            return func.HttpResponse(json.dumps(error), status_code=error[1])
        
        username = data['username']  # Assume username is available in request after authentication
        email_token=data['email_token']
        new_password = data['new_password']

        # Check if user exists
        user_exists_flag, partition_key, user_data = user_exists(username=username)
        if not user_exists_flag:
            return func.HttpResponse(
                json.dumps({"error": "User not found."}),
                status_code=404
            )

        # Retrieve user entity and Check if the provided email token matches
        user_entity = user_client.get_entity(partition_key=partition_key, row_key=username)
        if user_entity['email_token'] != email_token:
            return func.HttpResponse(
                json.dumps({"error": "Invalid or expired email token."}),
                status_code=401
            )
        
        # Hash the new password and update in the Users table
        hashed_new_password = hash_password(new_password)
        
        user_entity['password'] = hashed_new_password
        user_entity['confirm_email'] = True

        user_client.update_entity(entity=user_entity)
        logging.info(f"Password updated successfully for user: {username}")

        # Send a confirmation email
        user_data = {
            'action': 'change_password',
            'username': user_entity['RowKey'],
            'email': user_entity['email'],
            'login_ip': req.headers.get("X-Forwarded-For", req.headers.get("REMOTE_ADDR", "unknown")),
            'login_time': datetime.datetime.utcnow().strftime('%B %d, %Y %H:%M:%S')
        }
        encoded_email = base64.b64encode(json.dumps(user_data).encode('utf-8')).decode('utf-8')
        email_queue_client.send_message(encoded_email)
        logging.info(f"Email queue message sent for {username} password change")


        return func.HttpResponse(json.dumps({"message": "Password changed successfully."}), status_code=200)

    except Exception as e:
        logging.error(f"Error changing password for user '{username}': {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Internal server error", "message": str(e)}),
            status_code=500
        )


@app.function_name(name="resend_confirmation_token")
@app.route(route="resend_confirmation_token/{username}", methods=["POST"])
async def resend_confirmation_token(req: func.HttpRequest) -> func.HttpResponse:
    """
    Generate a new confirmation email token for the user and resend the confirmation email.

    Args:
        req (func.HttpRequest): The incoming HTTP request.
        username (str): The username of the user requesting the new token.

    Returns:
        func.HttpResponse: A JSON response indicating success or failure.
    """
    try:
        # Get the username from the URL route parameters
        username = req.route_params.get('username')

        # Check if the user exists using user_exists helper function
        user_exists_flag, partition_key, user_data = user_exists(username)

        if not user_exists_flag:
            # User not found
            return func.HttpResponse(
                json.dumps({"error": "User not found."}),
                status_code=404
            )
        
        # Generate new confirmation token and expiration time
        email_token, token_expires_at = generate_confirmation_token()

        # Update the user entity with the new token and expiration time
        user_entity = {
            'PartitionKey': partition_key,
            'RowKey': username,
            'email_token': email_token,
            'token_expires_at': token_expires_at
        }

        # Update the user entity in the Users table
        user_client.update_entity(entity=user_entity)

        # Send the new confirmation token to the email queue
        email_message = {
            "action": "resend_confirmation_token",
            "username": username,
            "email": user_data['email'],
            "email_token": email_token,
        }
        email_queue_client.send_message(json.dumps(email_message))
        
        logging.info(f"New confirmation token sent to {username}")

        return func.HttpResponse(
            json.dumps({"message": "New confirmation token sent."}),
            status_code=200
        )
    
    except Exception as e:
        logging.error(f"Error processing resend confirmation token request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Internal server error", "message": str(e)}),
            status_code=500
        )
