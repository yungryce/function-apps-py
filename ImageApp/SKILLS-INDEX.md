# Skills Index

This document maps specific technical skills to their implementations within this project.

## Serverless Architecture
- **Function App Structure**: [function_app.py](./function_app.py#L10-L20)
- **Route Definitions**: [function_app.py](./function_app.py#L87)
- **HTTP Triggers**: [function_app.py](./function_app.py#L87-L167)

## Image Processing
- **Compression Algorithm**: [function_app.py](./function_app.py#L31-L63)
- **Format Preservation**: [function_app.py](./function_app.py#L39-L40)
- **MIME Type Detection**: [function_app.py](./function_app.py#L135-L144)

## Cloud Storage Integration
- **Blob Service Client**: [function_app.py](./function_app.py#L98-L100)
- **Container Management**: [function_app.py](./function_app.py#L23-L30)
- **Blob Upload Operations**: [function_app.py](./function_app.py#L100-L101)
- **Blob Download Operations**: [function_app.py](./function_app.py#L134)

## Error Handling & Input Validation
- **Request Validation**: [function_app.py](./function_app.py#L89-L91)
- **Size Limits**: [function_app.py](./function_app.py#L94-L96)
- **Exception Handling**: [function_app.py](./function_app.py#L87-L106)
- **Blob Existence Check**: [function_app.py](./function_app.py#L128-L130)

## CI/CD Pipeline
- **GitHub Actions Workflow**: [.github/workflows/image_deploy.yml](./.github/workflows/image_deploy.yml)
- **Python Environment Setup**: [.github/workflows/image_deploy.yml](./.github/workflows/image_deploy.yml#L14-L25)
- **Azure Login**: [.github/workflows/image_deploy.yml](./.github/workflows/image_deploy.yml#L27-L29)
- **Function Deployment**: [.github/workflows/image_deploy.yml](./.github/workflows/image_deploy.yml#L42-L44)

## API Design
- **RESTful Endpoints**: [function_app.py](./function_app.py#L87-L167)
- **Response Formatting**: [function_app.py](./function_app.py#L162-L167)
- **Status Code Usage**: [function_app.py](./function_app.py#L90-L166)

## Logging & Monitoring
- **Structured Logging**: [function_app.py](./function_app.py#L54)
- **Error Reporting**: [function_app.py](./function_app.py#L105)
- **Application Insights Integration**: [host.json](./host.json#L3-L9)
