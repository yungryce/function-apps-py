# Azure Function for reCAPTCHA Enterprise Validation

This serverless Azure Function provides a secure backend service for validating Google reCAPTCHA Enterprise tokens, helping to protect your applications from bots, spam, and automated abuse.

## Features

- Serverless HTTP endpoint for validating reCAPTCHA tokens
- Integration with Google reCAPTCHA Enterprise API
- Service account authentication with Google Cloud
- Structured JSON API responses
- Comprehensive error handling
- Action verification to prevent token reuse

## Prerequisites

- Azure subscription with Function App service
- Google Cloud project with reCAPTCHA Enterprise enabled
- Google Cloud service account with reCAPTCHA Enterprise access
- reCAPTCHA Enterprise site key configured for your domain

## Environment Variables

The function requires the following environment variables:

- `GOOGLE_APPLICATION_CREDENTIALS_JSON`: Service account JSON credentials
- `GOOGLE_CLOUD_PROJECT_ID`: Your Google Cloud project ID
- `RECAPTCHA_SITE_KEY`: Your reCAPTCHA Enterprise site key

## API Usage

### Request Format

```json
POST /api/verify_recaptcha
Content-Type: application/json

{
  "token": "RECAPTCHA_TOKEN_FROM_CLIENT",
  "action": "EXPECTED_ACTION_NAME"
}
```

### Response Format

```json
{
  "status": 200,
  "message": "Success",
  "error": null,
  "data": {
    "score": 0.9,
    "reasons": []
  }
}
```

The `score` field ranges from 0.0 to 1.0, where higher values indicate a higher likelihood of legitimate human interaction.

## Deployment

1. Clone this repository
2. Set up environment variables in your Azure Function App
3. Deploy the function using Azure Functions Core Tools or VS Code extension

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
func start
```

## Security Considerations

- Store your Google Cloud credentials securely
- Consider implementing additional authorization on the function
- Set appropriate score thresholds based on your application needs
- Monitor usage patterns for potential abuse

az role assignment create --assignee <clientId> --role Contributor --scope /subscriptions/<subscriptionId>/resourceGroups/<resource-group>/providers/Microsoft.Web/sites/<function-app-name>
