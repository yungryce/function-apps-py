# Authentication Function App - Project Manifest

## Project Identity
- **Name**: Authentication Function App
- **Type**: API
- **Scope**: Azure Functions Application
- **Status**: Functional Demo

## Technology Signature
- **Runtime**: Python 3.7+
- **Framework**: Azure Functions v4
- **Primary Storage**: Azure Table Storage
- **Message Queue**: Azure Queue Storage
- **Authentication**: JWT (JSON Web Tokens)
- **Security Features**: Rate limiting, IP validation, Token blacklisting

## Demonstrated Competencies
- Implementation of JWT-based authentication
- Serverless architecture design
- Asynchronous processing of user events
- Secure credential storage
- Rate limiting for API protection
- IP-based access control
- Token expiration and blacklisting
- Integration with external email service
- Error handling and logging

## System Context
This app serves as a standalone authentication service that can be integrated with any client application. It handles user registration, authentication, and account management, while delegating email notifications to a separate function app.

## Deployment Requirements
- Azure Functions service
- Azure Storage Account (for Tables and Queues)
- Environment variables for secrets and configuration

## Development Workflow
1. Local development using Azure Functions Core Tools
2. Testing with shell scripts or Postman
3. Deployment via GitHub Actions to Azure

## Maintenance Notes
- The app uses in-memory rate limiting that resets when the function app restarts
- Token cleanup runs on a daily cron schedule
- Email confirmation and notifications are handled by a separate function app