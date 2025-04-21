# Skills Index

This document maps specific technical skills to their implementations within this project.

## Serverless Architecture
- **Azure Functions Setup**: [function_app.py](./function_app.py#L10-L20)
- **Queue Trigger Configuration**: [function_app.py](./function_app.py#L23-L25)

## Email Integration
- **SMTP Configuration**: [helper_functions.py](./helper_functions.py#L17-L22)
- **Email Formatting**: [helper_functions.py](./helper_functions.py#L24-L29)
- **Error Handling**: [helper_functions.py](./helper_functions.py#L33-L37)

## Message Processing
- **Queue Message Parsing**: [function_app.py](./function_app.py#L41-L44)
- **Action Routing Logic**: [function_app.py](./function_app.py#L46-L65)

## User Management Notifications
- **Registration Email**: [function_app.py](./function_app.py#L78-L104)
- **Login Notification**: [function_app.py](./function_app.py#L107-L139)
- **Password Management**: [function_app.py](./function_app.py#L271-L295)
- **Account Deletion Flow**: [function_app.py](./function_app.py#L202-L229)

## CI/CD Pipeline
- **GitHub Actions Workflow**: [.github/workflows/master_emailapp.yml](./.github/workflows/master_emailapp.yml)
- **Python Environment Setup**: [.github/workflows/master_emailapp.yml](./.github/workflows/master_emailapp.yml#L17-L22)
- **Azure Functions Deployment**: [.github/workflows/master_emailapp.yml](./.github/workflows/master_emailapp.yml#L47-L53)

## Security Practices
- **Environment Variable Usage**: [helper_functions.py](./helper_functions.py#L17-L22)
- **Azure KeyVault Integration**: [README.md](./README.md#L67-L68)