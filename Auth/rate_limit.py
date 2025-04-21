import datetime
from collections import defaultdict
from datetime import datetime, timedelta

# rate_limits = defaultdict(list)  # Tracks requests per identifier
# In-memory store for rate limiting (this will reset on function app restarts)
rate_limits = {}
ip_limits = {}

def is_rate_limited(identifier: str) -> bool:
    """
    Check if a user (based on username or email) is rate limited.

    Args:
        identifier (str): The identifier (username or email) of the user.
        max_requests (int): Maximum requests allowed.
        time_window (int): Time window in seconds.

    Returns:
        bool: True if the user is rate limited, False otherwise.
    """
    MAX_REQUESTS = 5  # Max requests allowed per time window
    TIME_WINDOW = 60  # Time window in seconds

    current_time = datetime.now()
    
    # If identifier is not in rate_limits, initialize an empty list
    if identifier not in rate_limits:
        rate_limits[identifier] = []

    # Remove timestamps older than the time window
    rate_limits[identifier] = [
        timestamp for timestamp in rate_limits[identifier] 
        if timestamp > current_time - timedelta(seconds=TIME_WINDOW)
    ]

    # Check if the current requests exceed the allowed limit
    if len(rate_limits[identifier]) >= MAX_REQUESTS:
        return True  # User is rate limited

    # Add the current timestamp for this identifier
    rate_limits[identifier].append(current_time)
    
    return False  # User is not rate limited


def is_ip_rate_limited(ip_address: str) -> bool:
    """
    Check if an IP address is rate limited.

    Args:
        ip_address (str): The IP address of the user.

    Returns:
        bool: True if the IP address is rate limited, False otherwise.
    """
    IP_MAX_REQUESTS = 4  # Max requests allowed per time window
    IP_TIME_WINDOW = 60  # Time window in seconds
    current_time = datetime.now()

    if ip_address not in ip_limits:
        ip_limits[ip_address] = []

    # Remove timestamps older than the time window
    ip_limits[ip_address] = [timestamp for timestamp in ip_limits[ip_address] if timestamp > current_time - timedelta(seconds=IP_TIME_WINDOW)]

    # Check if the current requests exceed the allowed limit
    if len(ip_limits[ip_address]) >= IP_MAX_REQUESTS:
        return True  # IP is rate limited

    # Add the current timestamp
    ip_limits[ip_address].append(current_time)
    return False  # IP is not rate limited