# Architecture Diagram

```mermaid
graph TD
    A[Client Application] -->|sends reCAPTCHA token| B[Azure Function]
    B -->|extracts token & action| C[Request Validation]
    C -->|if valid| D[Google Service Account Auth]
    C -->|if invalid| E[Return Error Response]
    D -->|authenticated client| F[reCAPTCHA Enterprise API]
    F -->|creates assessment| G[Token Validation]
    G -->|if valid token| H[Action Verification]
    G -->|if invalid token| I[Return Failure Response]
    H -->|if action matches| J[Risk Analysis]
    H -->|if action mismatch| K[Return Failure Response]
    J -->|formats results| L[Return Success Response]
    
    style A fill:#f9f,stroke:#333,stroke-width:2px
    style B fill:#bbf,stroke:#333,stroke-width:2px
    style F fill:#bfb,stroke:#333,stroke-width:2px
```

## System Components

### Client Side
- Web/mobile application implements reCAPTCHA Enterprise
- Client generates a token upon user interaction
- Token and action name sent to Azure Function

### Azure Function
- Serverless HTTP endpoint receives token verification requests
- Authenticates with Google Cloud using service account
- Communicates with reCAPTCHA Enterprise API
- Processes risk assessment responses
- Returns structured API responses

### Google reCAPTCHA Enterprise
- Validates tokens against expected actions
- Performs risk analysis using machine learning
- Provides fraud detection scores and risk reasons

## Data Flow

1. User interacts with protected element on client application
2. Client-side reCAPTCHA generates a token
3. Application sends token to Azure Function endpoint
4. Function authenticates with Google Cloud
5. Function creates assessment request with token
6. Google reCAPTCHA Enterprise evaluates the token
7. Assessment results returned with risk score and reasons
8. Function formats and returns API response to client
9. Client application takes appropriate action based on risk score