import asyncio
from functools import wraps
from helper_functions import table_service, ip_checker, confirm_email
from azure.core.exceptions import ResourceNotFoundError
import json
import jwt
import os
import logging
from azure.functions import HttpResponse
from azure.storage.queue import QueueServiceClient
import base64


SECRET_KEY = os.getenv("SECRET_KEY")
connection_string = os.getenv("AzureWebJobsStorage")
queue_service_client = QueueServiceClient.from_connection_string(conn_str=connection_string)


def authenticate(func):
    @wraps(func)
    async def wrapper(req, *args, **kwargs):
        """
        Authenticate the user by verifying the JWT token in the request headers.
        If the token is valid, it will be added to the blacklist to prevent replay attacks.
        """

        auth_header = req.headers.get("Authorization", None)

        # Check if Authorization header is present
        if not auth_header:
            return HttpResponse(
                json.dumps({'error': 'Authorization header is missing'}),
                status_code=401
            )

        # Check if the header contains a Bearer token
        if not auth_header.startswith("Bearer "):
            return HttpResponse(
                json.dumps({'error': 'Authorization header is malformed'}),
                status_code=401
            )

        try:
            # Extract the token after 'Bearer '
            token = auth_header.split(" ")[1]
        except IndexError:
            return HttpResponse(
                json.dumps({'error': 'Token is missing'}),
                status_code=401
            )

        try:
            # Decode and verify token
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            username = payload.get('sub')

            # If no username in token, reject it
            if not username:
                return HttpResponse(
                    json.dumps({'error': 'Token is invalid (no username found)'}),
                    status_code=401
                )
                
            # Check if the user's email is confirmed
            if not await confirm_email(username):
                return HttpResponse(
                    json.dumps({'error': 'Email not confirmed. Please verify your email.'}),
                    status_code=401
                )
                
            # Check if the IP address is allowed
            ip_address = req.headers.get("X-Forwarded-For", req.headers.get("REMOTE_ADDR"))  # Get IP address
            if not await ip_checker(username, ip_address):
                return HttpResponse(
                    json.dumps({'error': 'IP address not authorized, re-login to update'}),
                    status_code=401
                )

            # Check if token is blacklisted
            try:
                blacklist_client = table_service.get_table_client(table_name="Blacklist")
                blacklist_entity = blacklist_client.get_entity(partition_key=username, row_key=token)
                if blacklist_entity['active'] == False:
                    return HttpResponse(
                        json.dumps({'error': 'Token is blacklisted'}),
                        status_code=401
                    )
            except ResourceNotFoundError:
                # This is OK if no blacklist entry exists for the token
                pass
            except Exception as e:
                logging.error(f"Error checking blacklist for user {username}: {str(e)}")
                return HttpResponse(
                    json.dumps({'error': 'Error checking token blacklist', 'message': str(e)}),
                    status_code=500
                )

        except jwt.ExpiredSignatureError:
            # Send a message to the queue to mark the token as inactive
            try:
                # Get the queue client for sending the message
                queue_client = queue_service_client.get_queue_client("user-action-queue")
                
                # Create the message with the required data
                message = {
                    'action': 'update_expired_token',
                    'username': username,
                    'token': token
                }
                
                # Encode the message in base64 and send to the queue
                encoded_message = base64.b64encode(json.dumps(message).encode('utf-8')).decode('utf-8')
                queue_client.send_message(encoded_message)
                
                logging.info(f"Enqueued action to update expired token for user {username}.")
            
            except Exception as e:
                logging.error(f"Failed to enqueue expired token update for user {username}: {str(e)}")
            
            return func.HttpResponse(
                json.dumps({'error': 'Token has expired'}),
                status_code=401
            )
        except jwt.InvalidTokenError:
            return HttpResponse(
                json.dumps({'error': 'Invalid token'}),
                status_code=401
            )
        except jwt.DecodeError:
            return HttpResponse(
                json.dumps({'error': 'Token is not properly formatted'}),
                status_code=401
            )
        except Exception as e:
            logging.error(f"JWT decoding error: {str(e)}")
            return HttpResponse(
                json.dumps({'error': 'Failed to decode token', 'message': str(e)}),
                status_code=500
            )
    
        try:
            # Fetch user from the database using the username
            user_client = table_service.get_table_client(table_name="Users")
            user_entity = user_client.get_entity(partition_key=username, row_key=username)

            # Check if the account is deleted
            if user_entity.get('is_deleted', False):
                return HttpResponse(
                    json.dumps({'error': 'User account is deleted'}),
                    status_code=401
                )

            # Ensure required fields exist in the user entity
            if not all(k in user_entity for k in ('RowKey', 'email', 'first_name', 'last_name')):
                return HttpResponse(
                    json.dumps({'error': 'User entity is missing required fields'}),
                    status_code=500
                )

            user_data = {
                'username': user_entity['RowKey'],
                'email': user_entity['email'],
                'first_name': user_entity['first_name'],
                'last_name': user_entity['last_name']
            }

            # Attach user object and token to the request for later use
            req.user = user_data
            req.token = token

        except ResourceNotFoundError:
            return HttpResponse(
                json.dumps({'error': 'User not found'}),
                status_code=404
            )
        except PermissionError as pe:
            logging.error(f"Permission denied when accessing user table: {str(pe)}")
            return HttpResponse(
                json.dumps({'error': 'Permission denied'}),
                status_code=403
            )
        except Exception as e:
            logging.error(f"Error fetching user entity: {str(e)}")
            return HttpResponse(
                json.dumps({'error': 'An error occurred', 'message': str(e)}),
                status_code=500
            )
        
        # Call the original function with any provided arguments
        if asyncio.iscoroutinefunction(func):
            return await func(req, *args, **kwargs)
        else:
            return func(req, *args, **kwargs)
        
    return wrapper
