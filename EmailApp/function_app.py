import os
import json
import logging
import azure.functions as func
from azure.storage.queue import QueueClient
from helper_functions import send_email


app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# Retrieve the connection string from environment variables
CONNECTION_STRING = os.getenv('AzureWebJobsStorage')

# Initialize the Queue Client
queue_client = QueueClient.from_connection_string(CONNECTION_STRING, "emailqueue")


@app.function_name(name="EmailSender")
@app.queue_trigger(arg_name="msg", queue_name="emailqueue", connection="AzureWebJobsStorage")
async def push_email(msg: func.QueueMessage) -> None:
    """
    Processes a message from the email queue and sends an email.
    Args: 
        msg: The incoming queue message
        queue_name: The name of the queue
        connection: The connection string for the storage account

    Returns: None

    """
    logging.info(f"Processing message: {msg.get_body().decode()}")
    message = json.loads(msg.get_body().decode())
    action = message.get('action')

    if action == 'signup':
        await register_email(message)
    elif action == 'login':
        await login_email(message)
    elif  action == 'logout':
        await logout_email(message)
    elif action == 'delete_user':
        await delete_user_email(message)
    elif action == 'confirm_email':
        await verify_email(message)
    elif action == 'notify':
        await notify_user(message)
    elif action == 'forgot_password':
        await forgot_password_email
    elif action == 'change_password':
        await change_password_email(message)
    elif action == 'resend_confirmation_token':
        await resend_confirmation_token_email(message)
    else:
        logging.warning(f"Unknown action: {action}")


async def register_email(message):
    """
    Sends a registration confirmation email to the user.
    
    Args:
        message (dict): The message containing user details (from the queue).
        
    Returns:
        None
    """
    try:
        # Extract user data from the message
        to_email = message.get('email')
        first_name = message.get('first_name')
        last_name = message.get('last_name')
        username = message.get('username')
        email_token = message.get('email_token')


        # Compose the email content
        subject = "Welcome to Our Platform!"
        body = f"Dear {first_name} {last_name},\n\n" \
               f"Thank you for registering with us! Your username is {username}.\n" \
               f"Your confirmation token is: {email_token}\n\n" \
               "We are excited to have you on board. If you have any questions, feel free to contact us.\n\n" \
               "Best regards,\nThe Team"

        # Send the email using the send_email helper function
        send_email(to_email, subject, body)

        logging.info(f"Registration email sent successfully to {to_email}.")
    except Exception as e:
        logging.error(f"Failed to send registration email: {str(e)}")


async def login_email(message):
    """
    Sends an email notification to the user after a successful login.
    Includes a warning if the login did not originate from the user,
    and provides a link to reset their password.

    Args:
        message (dict): The message containing user details and login information (from the queue).
        
    Returns:
        None
    """
    try:
        # Extract user data and login details from the message
        to_email = message.get('email')
        first_name = message.get('first_name')
        last_name = message.get('last_name')
        username = message.get('username')
        login_ip = message.get('login_ip', 'Unknown IP')
        login_time = message.get('login_time', 'Unknown time')

        # Compose the email content
        subject = "Account Login Notification"

        body = f"Dear {first_name} {last_name},\n\n" \
            f"We noticed a login to your account (Username: {username}) on {login_time} from {login_ip}.\n\n" \
            "If this login attempt was made by you, no further action is required.\n\n" \
            "If this login did not originate from you, we recommend that you reset your password immediately to secure your account.\n\n" \
            "Please visit your account profile to reset your password:\n" \
            "If you have any questions or need further assistance, feel free to contact us.\n\n" \
            "Best regards,\nThe Security Team"
        
        logging.warning(body)

        # Send the email using the send_email helper function
        send_email(to_email, subject, body)

        logging.info(f"Login notification email sent successfully to {to_email}.")
    except Exception as e:
        logging.error(f"Failed to send login notification email: {str(e)}")


async def logout_email(message):
    """
    Sends an email notification to the user upon logout.

    Args:
        message (dict): A dictionary containing user data and action details, including:
                        - username
                        - email
                        - first_name
                        - last_name
                        - login_ip (if available)
                        - logout_time

    Returns:
        None
    """
    # Extract user details from the message
    username = message.get('username')
    email = message.get('email')
    first_name = message.get('first_name')
    last_name = message.get('last_name')
    logout_time = message.get('logout_time')  # This should be included in the message
    logout_ip = message.get('logout_ip', 'Unknown IP')  # Default to 'Unknown IP' if not available

    # Email body with logout notification
    body = f"Dear {first_name} {last_name},\n\n" \
           f"We noticed that you logged out of your account (Username: {username}) on {logout_time} from {logout_ip}.\n\n" \
           "If this logout was done by you, no further action is required.\n\n" \
           "If you did not initiate this logout, please log in again and update your password to secure your account.\n\n" \
           "You can visit your account profile to reset your password or review account activity:\n" \
           "If you have any questions or need further assistance, feel free to contact us.\n\n" \
           "Best regards,\nThe Security Team"
    logging.error(f"{body}")

    # Subject of the email
    subject = "Logout Notification - Your Account"

    # Send the email using the send_email function
    try:
        send_email(to_email=email, subject=subject, body=body)
        logging.info(f"Logout notification email sent to {email} successfully.")
    except Exception as e:
        logging.error(f"Failed to send logout email to {email}: {str(e)}")


async def delete_user_email(message):
    """
    Sends an email notification to the user upon account deletion.

    Args:
        message (dict): A dictionary containing user data and action details, including:
                        - username
                        - email
                        - first_name
                        - last_name
                        - deletion_time

    Returns:
        None
    """
    # Extract user details from the message
    username = message.get('username')
    email = message.get('email')
    first_name = message.get('first_name')
    last_name = message.get('last_name')
    deletion_time = message.get('deletion_time')  # Ensure this is passed in the message

    # Email body with account deletion notification
    body = f"Dear {first_name} {last_name},\n\n" \
           f"We want to confirm that your account (Username: {username}) has been successfully deleted on {deletion_time}.\n\n" \
           "If this account deletion was initiated by you, no further action is required.\n\n" \
           "However, if you did not request this deletion, please contact our support team immediately for assistance.\n\n" \
           "Please note that once your account is deleted, all associated data, including personal information, will be permanently removed from our system.\n\n" \
           "If you have any questions or need further assistance, feel free to contact us.\n\n" \
           "Best regards,\nThe Security Team"

    # Subject of the email
    subject = "Account Deletion Confirmation"

    # Send the email using the send_email function
    try:
        send_email(to_email=email, subject=subject, body=body)
        logging.info(f"Account deletion confirmation email sent to {email} successfully.")
    except Exception as e:
        logging.error(f"Failed to send account deletion email to {email}: {str(e)}")


async def forgot_password_email(message):
    """
    Sends a forgot password email to the user.
    
    Args:
        message (dict): The message containing user details (from the queue).
        
    Returns:
        None
    """
    try:
        # Extract user data from the message
        to_email = message.get('email')
        email_token = message.get('email_token')
        token_expires_at = message.get('token_expires_at')
        
        # Compose the email content
        subject = "Password Reset Request"
        body = f"Dear User,\n\n" \
               f"We received a request to reset your password.\n" \
               f"Your password reset token is: {email_token}\n" \
               f"This token will expire on {token_expires_at}.\n\n" \
               f"If you did not request this, please ignore this email. " \
               f"Otherwise, use the token to reset your password.\n\n" \
               "Best regards,\nThe Team"
        
        # Send the email using the send_email helper function
        send_email(to_email, subject, body)

        logging.info(f"Password reset email sent successfully to {to_email}.")
    except Exception as e:
        logging.error(f"Failed to send password reset email: {str(e)}")


async def change_password_email(message):
    """
    Sends an email to the user after they successfully change their password.
    
    Args:
        message (dict): The message containing user details (from the queue).
        
    Returns:
        None
    """
    try:
        # Extract user data from the message
        to_email = message.get('email')
        username = message.get('username')
        change_time = message.get('change_time')  # Assuming change_time is included in the message
        login_ip = message.get('login_ip')  # IP address from where the change was made

        # Compose the email content
        subject = "Your Password Has Been Changed"
        body = f"Dear {username},\n\n" \
               f"This is a confirmation that your password was successfully changed on {change_time}.\n" \
               f"If this change was made by you, no further action is required.\n\n" \
               f"If you did not change your password or you suspect any suspicious activity, please contact our support team immediately.\n" \
               f"Login IP Address: {login_ip}\n\n" \
               "Best regards,\nThe Team"
        
        # Send the email using the send_email helper function
        send_email(to_email, subject, body)

        logging.info(f"Password change confirmation email sent successfully to {to_email}.")
    except Exception as e:
        logging.error(f"Failed to send password change confirmation email: {str(e)}")



async def verify_email(message):
    """
    Sends an email to the user to confirm their registration.

    Args:
        message (dict): A dictionary containing user data and action details, including:
                        - username
                        - email
                        - first_name
                        - last_name

    Returns:
        None
    """
    # Extract user details from the message
    username = message.get('username')
    email = message.get('email')
    first_name = message.get('first_name')
    last_name = message.get('last_name')

    # Email body with account confirmation message
    body = f"Dear {first_name} {last_name},\n\n" \
           f"Thank you for confirming your registration on our platform (Username: {username}).\n\n" \
           "You are now an active member of our community.\n\n" \
           "If you have any questions or need further assistance, feel free to contact us.\n\n" \
           "Best regards,\nThe Team"

    # Subject of the email
    subject = "Registration Confirmation"

    # Send the email using the send_email function
    try:
        send_email(to_email=email, subject=subject, body=body)
        logging.info(f"Registration confirmation email sent to {email} successfully.")
    except Exception as e:
        logging.error(f"Failed to send registration confirmation email to {email}: {str(e)}")



async def resend_confirmation_token_email(message):
    """
    Sends an email to the user with a new email confirmation token.
    
    Args:
        message (dict): The message containing user details (from the queue).
        
    Returns:
        None
    """
    try:
        # Extract user data from the message
        to_email = message.get('email')
        username = message.get('username')
        email_token = message.get('email_token')

        # Compose the email content
        subject = "Resend: Confirm Your Email Address"
        body = f"Dear {username},\n\n" \
               f"It seems you requested a new email confirmation token. Your confirmation token is:\n\n" \
               f"Token: {email_token}\n\n" \
               "Please use this token to confirm your email address.\n\n" \
               "If you did not request this, please ignore this email or contact our support team.\n\n" \
               "Best regards,\nThe Team"

        # Send the email using the send_email helper function
        send_email(to_email, subject, body)

        logging.info(f"Resend confirmation email sent successfully to {to_email}.")
    except Exception as e:
        logging.error(f"Failed to send resend confirmation email: {str(e)}")



async def notify_user(message):
    """
    Sends a general notification email to the user.

    Args:
        message (dict): A dictionary containing user data and action details, including:
                        - username
                        - email
                        - first_name
                        - last_name
                        - notification_message

    Returns:
        None
    """
    # Extract user details from the message
    username = message.get('username')
    email = message.get('email')
    first_name = message.get('first_name')
    last_name = message.get('last_name')
    notification_message = message.get('notification_message')  # Ensure this is passed in the message

    # Email body with the notification message
    body = f"Dear {first_name} {last_name},\n\n" \
           f"We have an important message for you regarding your account (Username: {username}).\n\n" \
           f"{notification_message}\n\n" \
           "If you have any questions or need further assistance, feel free to contact us.\n\n" \
           "Best regards,\nThe Support Team"

    # Subject of the email
    subject = "Important Notification"

    # Send the email using the send_email function
    try:
        send_email(to_email=email, subject=subject, body=body)
        logging.info(f"Notification email sent to {email} successfully.")
    except Exception as e:
        logging.error(f"Failed to send notification email to {email}: {str(e)}")




