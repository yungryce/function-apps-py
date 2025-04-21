# Azure Function Apps Collection

A comprehensive collection of serverless Azure Function applications demonstrating various cloud-native patterns, integrations, and security implementations. This repository serves as both a learning resource and a portfolio of practical Azure serverless solutions.

## 🌟 Overview

This monorepo contains several independent Azure Function applications, each focused on specific functionality and demonstrating different aspects of serverless architecture. Each subdirectory is a standalone project with its own documentation, architecture diagrams, and deployment instructions.

## 📂 Function Apps

| Function App | Description | Key Technologies |
|-------------|-------------|------------------|
| [Auth](./Auth/) | Complete authentication system with JWT tokens, rate limiting, and user management | Python, JWT, Azure Table Storage, Queue Storage |
| [EmailApp](./EmailApp/) | Email notification service triggered by queue messages | Python, Azure Queue Storage, SMTP, Azure KeyVault |
| [ImageApp](./ImageApp/) | Image upload, compression, and retrieval service | Python, Azure Blob Storage, Pillow |
| [recaptcha_FA](./recaptcha_FA/) | Google reCAPTCHA Enterprise token validation service | Python, Google Cloud API, Azure HTTP triggers |
| [startstopvm](./startstopvm/) | Automated VM management based on schedules | Python, Azure Compute SDK, Timer triggers |

## 🏗️ Repository Structure

Each function app follows a consistent structure:

```
function-app-folder/
├── .repo-context.json       # Project metadata
├── ARCHITECTURE.md          # Architecture diagrams and flows
├── README.md                # Documentation and usage instructions
├── function_app.py          # Main function implementations
├── host.json                # Function app configuration
└── requirements.txt         # Dependencies
```

## 🔑 Key Features

- **Serverless Architecture**: All solutions use Azure Functions for event-driven, scalable execution
- **Security Focus**: Implementations of authentication, validation, and secure configuration
- **Integration Patterns**: Various Azure service integrations (Storage, Queue, KeyVault)
- **Documentation**: Comprehensive architecture diagrams and implementation details
- **Best Practices**: Following Azure Function development and security best practices

## 🚀 Getting Started

### Prerequisites

- Azure subscription
- Azure Functions Core Tools v4+
- Python 3.7+
- Azure CLI (optional, for deployment)

### Running Locally

Each function app has its own setup instructions in its README.md file, but the general pattern is:

1. Navigate to the function app directory
2. Create a `local.settings.json` file with required environment variables
3. Install dependencies: `pip install -r requirements.txt`
4. Run locally: `func start`

### Deployment

Deploy individual function apps using Azure Functions Core Tools:

```bash
cd function-app-directory
func azure functionapp publish <app-name>
```

Or use the GitHub Actions workflows provided in each project.

## 🔒 Security Considerations

- All sensitive configuration is stored in environment variables
- Production deployments should use Azure KeyVault for secrets
- Authentication tokens have appropriate expiration and validation
- Rate limiting is implemented where applicable
- Input validation across all services

## 📚 Learning Resources

This repository demonstrates implementation of concepts from:

- [Azure Functions Documentation](https://docs.microsoft.com/en-us/azure/azure-functions/)
- [Serverless Architectures on Azure](https://docs.microsoft.com/en-us/azure/architecture/reference-architectures/serverless/)
- [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns)

## 🧪 Testing

Each function app contains testing instructions in its README.md file. Testing approaches include:

- Shell scripts for HTTP endpoint testing
- Azure Functions Core Tools for local execution
- Azure Portal for monitoring and diagnostics

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

