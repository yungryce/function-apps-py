# Azure Function App: Start and Stop VM

An automated cloud solution that manages the lifecycle of Azure Virtual Machines based on a predefined schedule. This serverless application utilizes Azure Functions with timer triggers to start VMs at the beginning of business hours and stop them at the end, optimizing cloud resource costs.

## 🎯 Features

- **Scheduled VM Management**: Automatically starts VMs at 7 AM and stops at 5 PM on weekdays
- **Managed Identity Authentication**: Secure, credential-free authentication to Azure resources
- **Error Resilience**: Comprehensive error handling and logging for operational visibility
- **CI/CD Integration**: Automated deployment pipeline via GitHub Actions
- **Cost Optimization**: Reduces cloud expenses by ensuring VMs run only during business hours

## 🔧 Technologies

- **Runtime**: Python 3.10
- **Framework**: Azure Functions v4
- **Authentication**: Azure DefaultAzureCredential
- **Key Libraries**: azure-functions, azure-mgmt-compute, azure-identity
- **DevOps**: GitHub Actions, Azure Functions Core Tools

## 🏗️ Architecture

This project implements a serverless architecture pattern with scheduled triggers. For detailed architecture information, see [ARCHITECTURE.md](./ARCHITECTURE.md).

## ⚙️ Configuration

### Environment Variables

Configure the following variables in your Azure Function App settings:

| Variable | Description | Example |
|----------|-------------|---------|
| `AZURE_SUBSCRIPTION_ID` | Your Azure subscription identifier | `12345678-1234-1234-1234-123456789abc` |
| `RESOURCE_GROUP` | Resource group containing the VM | `Lab-Win11` |
| `VM_NAME` | Name of the target virtual machine | `win11` |

## 🚀 Deployment

The application is deployed automatically via GitHub Actions when changes are pushed to the master branch.

### Manual Deployment

```bash
# Install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Login to Azure
az login

# Deploy the function
func azure functionapp publish startstopvmapp --python
```

## 📋 Skills Demonstrated

This project showcases several technical competencies. For a detailed mapping of skills to implementations, see [SKILLS-INDEX.md](./SKILLS-INDEX.md).

## 🔍 Monitoring

Monitor function execution through:

- Azure Portal > Function App > Monitor
- Application Insights for detailed telemetry
- Function App logs via: `az functionapp logs tail --name startstopvmapp --resource-group YOUR_RESOURCE_GROUP`

## 🔒 Security Considerations

- Uses managed identities instead of service principals
- No credentials stored in code or configuration
- Minimal permission model with RBAC assignments

## 📄 License

This project is licensed under the MIT License.
