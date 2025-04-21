# Authentication Function App Architecture

This document outlines the architecture of the Authentication Function App.

## System Architecture

```mermaid
graph TD
    Client[Client Application] -->|HTTP Request| HttpTriggers[HTTP Trigger Functions]
    HttpTriggers -->|Validate/Process| Auth[Authentication Logic]
    Auth -->|Store| TableStorage[Azure Table Storage]
    Auth -->|Enqueue| Queue[Azure Queue Storage]
    Queue -->|Trigger| QueueTriggers[Queue Trigger Functions]
    QueueTriggers -->|Process/Update| TableStorage
    QueueTriggers -->|Send to| EmailQueue[Email Queue]
    EmailQueue -->|Trigger| EmailApp[Email Function App]
    CronTrigger[Cron Trigger] -->|Cleanup| TokenBlacklist[Token Blacklist]
    
    subgraph "Authentication Function App"
        HttpTriggers
        Auth
        QueueTriggers
        CronTrigger
    end
    
    subgraph "Azure Storage"
        TableStorage
        Queue
        EmailQueue
        TokenBlacklist
    end
```

## Component Flow

### Authentication Process
1. Client sends credentials to HTTP trigger function
2. System validates credentials against stored user data
3. If valid, a JWT token is generated and returned
4. User activity is logged in queue for async processing
5. Email notification is sent via Email Function App

### Data Storage Model
- **Users Table**: Stores user profiles and credentials
- **Blacklist Table**: Manages invalidated tokens
- **Action Queue**: Processes user events asynchronously
- **Email Queue**: Sends notifications to external email function app

### Key Components

#### HTTP Trigger Functions
- `register`: User registration with email validation
- `login`: Authenticates users and issues JWT tokens
- `logout`: Invalidates active tokens
- `get_user`/`get_all_users`: Retrieves user information
- `delete_user`: Marks accounts as deleted
- `verify_email`: Confirms user email addresses
- `forgot_password`: Initiates password reset process
- `change_password`: Updates user passwords
- `resend_confirmation_token`: Resends verification emails

#### Queue Trigger Functions
- Process user registrations
- Update user information
- Handle token invalidation
- Log user activity

#### Timer Trigger Functions
- `cleanup_expired_tokens`: Daily job to remove expired tokens from blacklist

#### Authentication Guard
- JWT token validation
- IP address validation
- Email confirmation verification
- Token blacklist checking

#### Rate Limiting
- In-memory tracking of request frequency
- Separate limits for username/email and IP address
- Configurable thresholds for request volume

## Security Considerations
- Passwords are hashed before storage
- JWT tokens have configurable expiration
- Rate limiting prevents brute force attacks
- IP validation prevents unauthorized access from new locations
- Blacklisted tokens prevent replay attacks
- Email verification required for sensitive operations
```

## Data Flow Diagram

```mermaid
sequenceDiagram
    participant Client
    participant API as Auth Function App
    participant TableDB as Azure Table Storage
    participant Queue as Azure Queue
    participant Email as Email Function App
    
    Client->>API: Register (username, password, email)
    API->>API: Validate & Rate Limit
    API->>Queue: Enqueue Registration
    API->>Client: Registration Pending
    
    Queue->>API: Process Registration
    API->>TableDB: Create User
    API->>Email: Send Confirmation
    Email->>Client: Email Verification Link
    
    Client->>API: Verify Email (token)
    API->>TableDB: Mark Email as Verified
    API->>Client: Confirmation
    
    Client->>API: Login (username, password)
    API->>TableDB: Validate Credentials
    API->>API: Generate JWT Token
    API->>Queue: Log Login Event
    API->>Client: Return JWT Token
    
    Client->>API: Protected Request + JWT
    API->>API: Validate JWT
    API->>Client: Protected Resource
    
    Client->>API: Logout
    API->>TableDB: Add Token to Blacklist
    API->>Queue: Log Logout Event
    API->>Client: Logout Confirmation
```