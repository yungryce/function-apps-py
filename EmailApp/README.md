# Azure Function App for Email Notifications

## Overview

This serverless Azure Function App provides a scalable solution for sending transactional emails based on user actions. The system processes queue messages to deliver personalized emails for user registration, authentication events, account management, and general notifications.

## Features

- **Queue-Triggered Processing**: Asynchronously handles email requests through Azure Storage Queues
- **Multiple Email Templates**: Supports various notification types (signup, login, logout, password reset, etc.)
- **Scalable Architecture**: Leverages Azure Functions' serverless model for cost-effective scaling
- **Secure Email Delivery**: Uses TLS for SMTP communication with configurable email providers
- **CI/CD Integration**: Automated deployment via GitHub Actions

## Architecture

![Architecture Diagram](./ARCHITECTURE.md)

The application consists of two main components:

1. **Email Queue**: An Azure Storage Queue that holds pending email requests
2. **Email Function**: A queue-triggered Azure Function that processes messages and sends emails

## Email Types Supported

- **User Registration**: Welcome emails for new users
- **Login Notifications**: Security alerts for account access
- **Logout Confirmations**: Notifications of session termination
- **Account Deletion**: Confirmation of account removal
- **Password Management**: Reset requests and change confirmations
- **Email Verification**: Account verification flows
- **General Notifications**: Custom user notifications

## Technical Implementation

- Python 3.10+
- Azure Functions v4
- Azure Storage Queue
- SMTP email delivery

## Prerequisites

- Azure subscription
- SMTP server credentials
- Python 3.10 or higher (for local development)

## Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd Email_FA
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   Create a `local.settings.json` file for local development:
   ```json
   {
     "IsEncrypted": false,
     "Values": {
       "AzureWebJobsStorage": "<storage-connection-string>",
       "FUNCTIONS_WORKER_RUNTIME": "python",
       "SMTP_SERVER": "smtp.example.com",
       "SMTP_PORT": "587",
       "SMTP_USER": "your-username",
       "SMTP_PASSWORD": "your-password",
       "SMTP_FROM_EMAIL": "noreply@example.com"
     }
   }
   ```

4. **Local Development**:
   ```bash
   func start
   ```

5. **Deploy to Azure**:
   ```bash
   func azure functionapp publish emailapp
   ```

## KeyVault Integration

For production environments, secure your credentials using Azure KeyVault:

```
@Microsoft.KeyVault(SecretUri=https://<YourVaultName>.vault.azure.net/secrets/<SecretName>/<SecretVersion>)
```

## CI/CD Pipeline

This project includes GitHub Actions workflows for continuous deployment:

- Automatic deployment on push to master branch
- Python dependency caching for faster builds
- Azure Functions Core Tools integration

## Helpful CLI Commands

### Fetch App Settings 
```bash
func azure functionapp fetch-app-settings <APP_NAME>
```

### Deploy Function App
```bash
func azure functionapp publish <APP_NAME>
```

## Testing

To test locally, you can:

1. Add messages to the queue via the Azure Portal
2. Use the Azure Functions Core Tools to trigger the function with sample data

## Skills Index

For a detailed mapping of technical skills implemented in this project, see [SKILLS-INDEX.md](./SKILLS-INDEX.md).

## Contributing

Contributions are welcome! Please create a pull request with your changes.

## License

This project is licensed under the MIT License.


