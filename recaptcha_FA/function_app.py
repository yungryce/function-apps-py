import logging
import os
import json
import azure.functions as func
from google.cloud import recaptchaenterprise_v1
from google.oauth2 import service_account
from google.cloud.recaptchaenterprise_v1 import Assessment


app = func.FunctionApp()

# Function to create assessment using Google reCAPTCHA Enterprise
def create_assessment(project_id: str, recaptcha_key: str, token: str, recaptcha_action: str) -> Assessment:
    """Create an assessment to analyze the risk of a UI action.
    Args:
        project_id: Your Google Cloud Project ID.
        recaptcha_key: The reCAPTCHA key associated with the site/app.
        token: The generated token obtained from the client.
        recaptcha_action: Action name corresponding to the token.
    Returns:
        Assessment: The assessment result containing the risk score.
    """
    # Get service account credentials from the environment variable
    service_account_info = json.loads(os.getenv('GOOGLE_APPLICATION_CREDENTIALS_JSON'))
    credentials = service_account.Credentials.from_service_account_info(service_account_info)

    client = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient(credentials=credentials)

    # Set the properties of the event to be tracked.
    event = recaptchaenterprise_v1.Event()
    event.site_key = recaptcha_key
    event.token = token

    assessment = recaptchaenterprise_v1.Assessment()
    assessment.event = event

    project_name = f"projects/{project_id}"

    # Build the assessment request.
    request = recaptchaenterprise_v1.CreateAssessmentRequest()
    request.assessment = assessment
    request.parent = project_name

    response = client.create_assessment(request)

    # Check if the token is valid.
    if not response.token_properties.valid:
        logging.error(f"Invalid token: {response.token_properties.invalid_reason}")
        return None

    # Check if the expected action was executed.
    if response.token_properties.action != recaptcha_action:
        logging.error("Action mismatch.")
        return None

    return response

@app.route(route="verify_recaptcha", auth_level=func.AuthLevel.ANONYMOUS)
def verify_recaptcha(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing request for reCAPTCHA token verification.")

    try:
        # Get data from request
        req_body = req.get_json()
        token = req_body.get('token')
        recaptcha_action = req_body.get('action')

        if not token or not recaptcha_action:
            return func.HttpResponse(
                json.dumps({
                    'status': 400,
                    'message': "Bad request: Token or action not provided.",
                    'error': None,
                    'data': None
                }),
                mimetype="application/json",
                status_code=400
            )

        # Set up your Google Cloud project ID and reCAPTCHA site key
        project_id = os.getenv('GOOGLE_CLOUD_PROJECT_ID')
        recaptcha_key = os.getenv('RECAPTCHA_SITE_KEY')

        # Call the create_assessment function
        assessment_response = create_assessment(project_id, recaptcha_key, token, recaptcha_action)

        if assessment_response is None:
            return func.HttpResponse(
                json.dumps({
                    'status': 400,
                    'message': "Token verification failed.",
                    'error': None,
                    'data': None
                }),
                mimetype="application/json",
                status_code=400
            )

        # Extract and return risk score and reasons
        score = assessment_response.risk_analysis.score
        reasons = assessment_response.risk_analysis.reasons

        result = {
            'score': score,
            'reasons': [str(reason) for reason in reasons]
        }

        logging.info(f"result: {result}")

        # Return the response in the ResponseInfo format
        return func.HttpResponse(
            json.dumps({
                'status': 200,
                'message': "Success",
                'error': None,
                'data': result
            }),
            mimetype="application/json",
            status_code=200
        )

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        return func.HttpResponse(
            json.dumps({
                'status': 500,
                'message': "Internal server error.",
                'error': str(e),
                'data': None
            }),
            mimetype="application/json",
            status_code=500
        )
