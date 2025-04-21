# Authentication Function App

## Overview

A serverless authentication system built with Azure Functions that provides comprehensive user management capabilities including registration, authentication, and account management. This app demonstrates best practices for implementing secure authentication in a cloud-native environment.

**Note**: This app is designed for learning and demonstration purposes and includes additional security considerations that would be needed for production use.

## Technology Signature

- **Language**: Python 3.7+
- **Framework**: Azure Functions v4
- **Storage**: Azure Table Storage
- **Message Processing**: Azure Queue Storage
- **Authentication**: JWT (JSON Web Tokens)
- **Scheduling**: Azure Functions Timer Trigger (CRON)

## Demonstrated Competencies

- Serverless API development
- Token-based authentication system
- Asynchronous event processing
- Rate limiting implementation
- Security best practices
- Cloud service integration

## System Context

The Authentication Function App serves as a standalone identity provider that can be integrated with various client applications. It handles the entire authentication lifecycle while delegating email notifications to a separate function app.

## Features

### Core Authentication

- **User Registration**: Create new user accounts with email verification
- **Login/Logout**: Secure authentication with JWT tokens
- **Password Management**: Reset and change password capabilities
- **Email Verification**: Verification process for new registrations
- **Account Management**: View and delete user accounts

### Security Features

- **JWT Authentication**: Token-based authentication with expiration
- **Guard Middleware**: Decorator-based authentication for protected routes
- **Rate Limiting**: Prevent abuse through request throttling
- **IP Validation**: Additional security by tracking user IP addresses
- **Token Blacklisting**: Prevent reuse of invalidated tokens
- **Expired Token Cleanup**: Automatic maintenance via timer trigger

### Integration

- **Queue-Based Processing**: Asynchronous handling of user events
- **Email Notifications**: Integration with external email service
- **Extensible Design**: Easy to integrate with other services

## Code Structure

- **`function_app.py`**: Main HTTP trigger endpoints
- **`guard.py`**: Authentication middleware decorator
- **`rate_limit.py`**: In-memory rate limiting implementation
- **`active_cron_trigger.py`**: Timer trigger for token cleanup
- **`queue_triggers.py`**: Queue processing functions
- **`helper_functions.py`**: Utility functions for common operations

## Setup and Configuration

### Prerequisites

- Azure subscription
- Azure Functions Core Tools v4
- Python 3.7+
- Azure CLI (optional, for deployment)

### Environment Variables

The following environment variables need to be configured:

```
AzureWebJobsStorage=<Storage account connection string>
SECRET_KEY=<JWT secret key>
EMAIL_STORAGE_CONNECTION_STRING=<Connection string for email queue>
```

### Local Development

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Set up local.settings.json with required environment variables
4. Run locally: `func start`

### Testing

Use the provided test scripts in the `/tests` directory to test the functionality:

- `test_register.sh` - Test user registration
- `test_login.sh` - Test login functionality
- `test_logout.sh` - Test logout functionality
- `test_others.sh` - Test other API endpoints

### Deployment

Deploy to Azure Functions using Azure CLI or GitHub Actions:

```bash
func azure functionapp publish <app-name>
```

Or use the provided GitHub Action workflow in `.github/workflows/`.

## Implementation Details

### Authentication Flow

1. User registers with email, username, and password
2. Confirmation email is sent with verification token
3. User verifies email by submitting token
4. User can log in with verified credentials
5. JWT token is issued and used for subsequent requests
6. Protected routes use the `@authenticate` decorator

### Rate Limiting Implementation

The app implements a basic in-memory rate limiter with:

- Per-user/email rate limits
- Per-IP address rate limits
- Configurable time windows and request thresholds

### Token Management

- Active tokens tracked in Azure Table Storage
- Blacklisted tokens during logout
- Expired tokens cleaned up daily via cron trigger

## Limitations and Considerations

- **In-Memory Rate Limiting**: Resets on function app restart
- **OAuth**: No support for OAuth authentication
- **Horizontal Scaling**: In-memory rate limiting does not work across instances
- **Production Use**: Additional security measures would be needed for production
- **Load Testing**: Not extensively tested for high load scenarios

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

[MIT License](LICENSE)
