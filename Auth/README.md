# Authentication App

## Overview

This authentication app is designed as a practice project for exploring authentication mechanisms in a serverless environment using Azure Functions. It is **not intended for use in production environments**.

The app features several authentication-related functions, integrated with Azure Services for scalable, serverless execution. It supports user registration, login, password changes, and email verification with an emphasis on security, rate limiting, and handling edge cases like expired tokens.

### Key Features:
- **Authentication**: Verifies user credentials using JWT tokens and an authentication guard.
- **Rate Limiting**: Protects against abuse by limiting the number of requests a user or IP can make.
- **Email Handling**: Email functionalities (like registration confirmation and password resets) are handled by another Azure Function app.
- **Azure Integration**: The app utilizes Azure Queues for processing actions and Azure Table Storage for user data storage.

## Architecture

## Authentication Workflow
The authentication is based on a **JWT token** that is included in the request headers. The token is verified using the `authenticate` guard before granting access to any protected route.

- **Backend**: Built on Azure Functions (v4), all outputs are queued using Azure Queues.
- **Data Storage**: Uses Azure Table Storage to store user information.
- **Email Handling**: Another function app is responsible for sending emails such as registration confirmation and password reset.

### Technologies Used:
- **Azure Functions**: The app is built using Azure Functions to handle HTTP requests, queue triggers, and timer triggers.
- **Azure Queues**: All outputs are queued for processing, ensuring asynchronous handling of actions like user registration.
- **Azure Table Storage**: User data, including sensitive details like passwords (hashed), is stored securely in Azure Table Storage.
- **Email Functionality**: Another Azure Function app handles user emails, including confirmations, password resets, etc.

### Triggers Implemented:
- **HTTP Triggers**: Handle incoming requests to functions like `register_email`, `login_email`, `logout_email`, etc.
- **Queue Triggers**: Handle user-related actions by processing messages from Azure Queues.
- **Timer Triggers**: Handles cleanup of expired tokens 

- **Core Functions**:
    - `register_email`: User registration.
    - `login_email`: Login process.
    - `logout_email`: Logout functionality.
    - `delete_user_email`: Deletion of user account.
    - `verify_email`: Email verification process.
    - `notify_user`: User notifications.
    - `forgot_password_email`: Forgot password email handling.
    - `change_password_email`: Change password functionality.
    - `resend_confirmation_token_email`: Resend verification token to the user.
    - `authenticate`: A guard wrapper to secure routes by authenticating JWT tokens.

## How It Works

1. **User Registration**: When a user registers, the app checks for rate limiting (based on email, username, and IP address). If valid, a registration request is queued for further processing, including email verification.

2. **Login and Logout**: The user’s credentials are validated, and after successful authentication, a JWT token is issued. The logout process invalidates the session and blacklists the token.

3. **Queue-Based Processing**: User-related actions (like registration, login, password reset) are processed asynchronously using Azure Queues. This helps maintain system scalability and reliability.

4. **Email Confirmation**: The app uses another Azure Function app to handle user email confirmation. A confirmation token is generated upon registration and sent to the user.

5. **Rate Limiting**: The app ensures that both users (by username or email) and IP addresses do not exceed a set number of requests in a given period.

### Example of the `authenticate` decorator:

```python
def authenticate(func):
    @wraps(func)
    async def wrapper(req, *args, **kwargs):
        # Authentication logic goes here
        ...
    return wrapper
```

## Setup and Deployment

## Prerequisites

Before you begin, ensure you have the following installed on your local machine:

- **Azure Functions Core Tools**: For running and testing Azure Functions locally.
  - Install guide: [Install Azure Functions Core Tools](https://docs.microsoft.com/en-us/azure/azure-functions/functions-run-local)
- **Azure CLI**: For managing Azure resources from the command line.
  - Install guide: [Install Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- **Python 3.7+**: The authentication app is built using Python.
  - Download Python: [Python Downloads](https://www.python.org/downloads/)
- **Visual Studio Code (VS Code)** with the **Azure Functions Extension** (optional but recommended for local debugging).
  - Install VS Code: [Download Visual Studio Code](https://code.visualstudio.com/)
  - Azure Functions Extension: [Install Azure Functions Extension](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azurefunctions)

## Step 1: Clone the Authentication App Repository

1. Open your terminal and run the following command to clone the repository:

    ```bash
    git clone https://github.com/yungryce/authentication-FA.git
    cd authentication-app
    ```

2. Ensure you are on the correct branch (e.g., `master`) and that the repository is up to date:

    ```bash
    git checkout master
    git pull origin master
    ```

## Step 2: Set Up Your Local Environment

### 1. Install Required Python Packages

Create a virtual environment and install the necessary dependencies.

```bash
python -m venv .env
source .env/bin/activate  # On Windows: .env\Scripts\activate
pip install -r requirements.txt
```

### 2. Start your function app locally:
```bash
func start
```

This will start your function app locally. You can now test your authentication endpoints.

## 3. Step 3: Test your functions
You can use a tool like Postman or cURL to test your endpoints.
```bash
curl -X POST http://localhost:7071/api/register -H "Content-Type: application/json" -d '{"username": "testuser", "email": "test@example.com", "password": "TestPassword123", "first_name": "John", "last_name": "Doe"}'
```

## Step 4: Deploy the Functions to Azure

Refer to the following Azure documentation to deploy your function apps:

- [Deploy Python Azure Functions](https://docs.microsoft.com/en-us/azure/azure-functions/functions-develop-python)
- [Azure Functions Documentation](https://docs.microsoft.com/en-us/azure/azure-functions/)


## Known Limitations

- **OAuth**: The app does not currently support OAuth for authentication.
- **Not for Production**: This app is intended for learning purposes only and is not designed for production environments.
- **Scalability**: While the app uses Azure's serverless offerings, performance may degrade with extremely high traffic or large-scale data handling due to its practice nature.
- **Security**: This app does not implement robust security measures like encryption for data at rest or in transit, which is crucial for real-world applications.
- **Error Handling**: The app lacks comprehensive error handling, which is essential for robust applications.
