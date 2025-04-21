import azure.functions as func
from azure.storage.blob import BlobServiceClient, BlobProperties
import logging
import os
from PIL import Image
from io import BytesIO


# Retrieve the connection string from environment variables
CONNECTION_STRING = os.getenv('AzureWebJobsStorage')

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

CONTAINER_NAME = 'image-files'
MAX_SIZE_KB = 20

# Ensure container exists
def ensure_container_exists():
    try:
        blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)
        container_client = blob_service_client.get_container_client(CONTAINER_NAME)
        
        # Create container if it doesn't exist
        if not container_client.exists():
            logging.info(f"Creating container {CONTAINER_NAME}")
            container_client.create_container()
            
        return True
    except Exception as e:
        logging.error(f"Error ensuring container exists: {e}")
        return False

# Compress Image Function
def compress_image(image_bytes, quality=95):
    """Compress the uploaded image and reduce quality if necessary."""
    try:
        image = Image.open(BytesIO(image_bytes))
    except Exception as e:
        logging.error(f"Error opening image: {e}")
        raise ValueError("Cannot open image file")
    
    # Get the original format or default to JPEG
    img_format = image.format if image.format else 'JPEG'
    
    output_io = BytesIO()

    # Loop to adjust quality until the image is under the specified size
    while True:
        output_io.seek(0)  # Reset buffer
        output_io.truncate()  # Clear the buffer
        image.save(output_io, format=img_format, quality=quality)
        
        # Calculate current image size
        image_data = output_io.getvalue()
        image_size_kb = len(image_data) / 1024  # Size in KB

        logging.info(f"Current compressed image size: {image_size_kb:.2f} KB with quality {quality}")

        # Break the loop if the image size is below the threshold
        if image_size_kb <= MAX_SIZE_KB or quality <= 10:  # Prevent quality from going below 10
            break
        
        # Decrease quality for the next iteration
        quality -= 5  # Reduce quality by 5 each iteration

    output_io.seek(0)
    return output_io, img_format


# Azure Function v2.0 with HTTP trigger and Blob output binding
@app.route(route="upload-image", methods=[func.HttpMethod.POST])  # HTTP Trigger
def upload_image(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Ensure container exists
        if not ensure_container_exists():
            return func.HttpResponse("Failed to access blob storage.", status_code=500)
            
        # Get uploaded image
        if not req.files or 'file' not in req.files:
            return func.HttpResponse("No file provided in the request.", status_code=400)
            
        image_data = req.files['file'].read()
        
        # Limit file size for initial upload (e.g., 10MB)
        if len(image_data) > 10 * 1024 * 1024:
            return func.HttpResponse("File too large. Maximum size is 10MB.", status_code=400)
        
        # Compress the image
        compressed_image, img_format = compress_image(image_data)

        # Generate dynamic blob name
        blob_name = f"{req.files['file'].filename}"

        # Upload compressed image to Blob Storage using connection string
        blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)

        blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
        blob_client.upload_blob(compressed_image, overwrite=True)

        logging.info('Compressed image uploaded to blob storage successfully')
        return func.HttpResponse(f"Image '{req.files['file'].filename}' compressed and uploaded successfully.", status_code=200)
    except Exception as e:
        logging.error(f"Error processing image: {e}")
        return func.HttpResponse("Failed to process image.", status_code=500)


# Function to fetch image from blob storage and return it to the user
@app.route(route="get-image/{image}", methods=[func.HttpMethod.GET])  # HTTP Trigger
def get_image(req: func.HttpRequest) -> func.HttpResponse:
    try:
        image_name = req.route_params.get('image')
        if not image_name:
            return func.HttpResponse("Image name not provided.", status_code=400)

        # Initialize BlobServiceClient using connection string
        blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)

        blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=image_name)
        
        # Check if blob exists
        if not blob_client.exists():
            return func.HttpResponse(f"Image '{image_name}' not found.", status_code=404)
            
        # Download blob content
        download_stream = blob_client.download_blob()
        image_bytes = download_stream.readall()
        
        # Determine MIME type based on file extension
        mime_type = "image/jpeg"  # Default
        if image_name.lower().endswith('.png'):
            mime_type = "image/png"
        elif image_name.lower().endswith('.gif'):
            mime_type = "image/gif"
        elif image_name.lower().endswith('.bmp'):
            mime_type = "image/bmp"
        elif image_name.lower().endswith('.webp'):
            mime_type = "image/webp"

        # Return the image as an HTTP response
        return func.HttpResponse(body=image_bytes, mimetype=mime_type, status_code=200)
    
    except Exception as e:
        logging.error(f"Error fetching image '{image_name if 'image_name' in locals() else 'unknown'}': {e}")
        return func.HttpResponse(f"Failed to fetch image.", status_code=500)


# Optional: Function to list all images in the container
@app.route(route="list-images", methods=[func.HttpMethod.GET])
def list_images(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Ensure container exists
        if not ensure_container_exists():
            return func.HttpResponse("Failed to access blob storage.", status_code=500)
            
        # Initialize BlobServiceClient using connection string
        blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)
        container_client = blob_service_client.get_container_client(CONTAINER_NAME)
        
        # List all blobs in the container
        blobs = container_client.list_blobs()
        blob_list = [blob.name for blob in blobs]
        
        # Return JSON response with the list of images
        import json
        return func.HttpResponse(
            body=json.dumps({"images": blob_list}),
            mimetype="application/json",
            status_code=200
        )
    except Exception as e:
        logging.error(f"Error listing images: {e}")
        return func.HttpResponse("Failed to list images.", status_code=500)
