import azure.functions as func
import datetime
import logging
import os
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient


# Storage account connection string
STORAGE_CONNECTION_STRING = os.getenv("AzureWebJobsStorage")

# Replace with your Azure subscription ID
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
if SUBSCRIPTION_ID:
    last_six_digits = SUBSCRIPTION_ID[-6:]
    logging.info(f'Last six digits of the subscription ID: {last_six_digits}')
else:
    logging.error('AZURE_SUBSCRIPTION_ID environment variable is not set')

# Replace with your VM's resource group and name
RESOURCE_GROUP = 'Lab-Win11'
VM_NAME = 'win11'

# Initialize the ComputeManagementClient
credential = DefaultAzureCredential()
compute_client = ComputeManagementClient(credential, SUBSCRIPTION_ID)

# Create the FunctionApp instance
app = func.FunctionApp()

def start_vm():
    try:
        logging.info(f'Starting VM {VM_NAME} in resource group {RESOURCE_GROUP}')
        compute_client.virtual_machines.begin_start(RESOURCE_GROUP, VM_NAME).result()
        logging.info(f'VM {VM_NAME} started successfully.')
    except Exception as e:
        logging.error(f'Failed to start VM {VM_NAME}: {str(e)}')

def stop_vm():
    try:
        logging.info(f'Stopping VM {VM_NAME} in resource group {RESOURCE_GROUP}')
        compute_client.virtual_machines.begin_power_off(RESOURCE_GROUP, VM_NAME).result()
        logging.info(f'VM {VM_NAME} stopped successfully.')
    except Exception as e:
        logging.error(f'Failed to stop VM {VM_NAME}: {str(e)}')


# Define the timer trigger schedule
@app.timer_trigger(schedule="0 0 6 * * 1-5", arg_name="mytimer", run_on_startup=False)  # 7 AM UTC+1 (6 AM UTC)
def startvm(mytimer: func.TimerRequest) -> None:
    utc_now = datetime.datetime.utcnow()
    logging.info('Start VM function ran at %s', utc_now)
    logging.info('Current cron schedule: %s', "0 6 * * *")
    start_vm()

@app.timer_trigger(schedule="0 0 16 * * 1-5", arg_name="mytimer", run_on_startup=False)  # 5 PM UTC+1 (4 PM UTC)
def stopvm(mytimer: func.TimerRequest) -> None:
    utc_now = datetime.datetime.utcnow()
    logging.info('Stop VM function ran at %s', utc_now)
    logging.info('Current cron schedule: %s', "0 16 * * *")
    stop_vm()

