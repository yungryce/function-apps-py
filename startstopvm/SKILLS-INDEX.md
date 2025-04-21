# Skills Index

This document maps specific technical skills to their implementations within this project.

## Serverless Architecture
- **Timer Trigger Definition**: [function_app.py](./function_app.py#L35-L46)

## Cloud Resource Management
- **VM Start Operation**: [function_app.py](./function_app.py#L17-L23)
- **VM Stop Operation**: [function_app.py](./function_app.py#L25-L31)

## Azure Identity & Security
- **Managed Identity Implementation**: [function_app.py](./function_app.py#L16)
- **Subscription Management**: [function_app.py](./function_app.py#L9-L14)

## CI/CD Automation
- **GitHub Actions Workflow**: [.github/workflows/app-deploy.yml](./.github/workflows/app-deploy.yml)
- **Deployment Caching Strategy**: [.github/workflows/app-deploy.yml](./.github/workflows/app-deploy.yml#L21-L33)

## Error Handling
- **Exception Handling**: [function_app.py](./function_app.py#L22-L23)
- **Comprehensive Logging**: [function_app.py](./function_app.py#L17-L21)

## Configuration Management
- **Environment Variables**: [function_app.py](./function_app.py#L9-L12)
- **Azure Function Configuration**: [host.json](./host.json)