import datetime
import logging
import azure.functions as func
from azure.data.tables import TableServiceClient
from helper_functions import table_service


# Create a blueprint for queue triggers
cp = func.Blueprint() 

# Initialize the TableServiceClient
# user_client = table_service.get_table_client(table_name="Users")
blacklist_client = table_service.get_table_client(table_name="Blacklist")


@cp.function_name(name="cleanup_expired_tokens")
@cp.timer_trigger(schedule="0 0 0 * * *", arg_name="mytimer", run_on_startup=False)  # 12 AM UTC+1 (0:00 AM UTC)
# @cp.timer_trigger(schedule="0 */5 * * * *", arg_name="mytimer", run_on_startup=False)  # 12 AM UTC+1 (0:00 AM UTC)
async def cleanup_expired_tokens(mytimer: func.TimerRequest) -> None:
    """Delete non-active tokens from the Blacklist table."""
    try:
        # Get the current UTC time and make it timezone-aware
        current_time = datetime.datetime.now(datetime.timezone.utc)

        # Query non-active tokens
        non_active_tokens = blacklist_client.query_entities(
            query_filter="active eq false"
        )

        # Loop through and delete expired tokens
        for token in non_active_tokens:
            # Check if the token is expired
            if token['expires_in'] < current_time:
                blacklist_client.delete_entity(partition_key=token['PartitionKey'], row_key=token['RowKey'])
                logging.info(f"Deleted expired token for user: {token['PartitionKey']}")

    except Exception as e:
        logging.error(f"Error while cleaning up expired tokens: {str(e)}")
