import os
import firebase_admin
from firebase_admin import credentials, firestore
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

def authorize_and_save_credentials(agent_id):
    # Set up the OAuth 2.0 flow
    flow = InstalledAppFlow.from_client_secrets_file(
        "servicesCredentials.json", SCOPES
    )

    # Run the OAuth 2.0 authorization flow
    credentials = flow.run_local_server(port=0)

    # Create a dictionary to store the token info
    credentials_info = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
        "expiry": credentials.expiry.isoformat() if credentials.expiry else None
    }

    # Save the token info to Firestore
    db = firestore.client()
    agent_ref = db.collection("AGENTS").document(agent_id)
    agent_ref.set({"gmailToken": credentials_info}, merge=True)

    print(f"Authorization complete and credentials saved for Agent ID: {agent_id}")

if __name__ == "__main__":
    # Initialize Firebase Admin SDK
    cred = credentials.Certificate("firebaseCredentials.json")
    firebase_admin.initialize_app(cred)

    # Define the OAuth 2.0 scope for complete Gmail access
    SCOPES = ["https://mail.google.com/"]
    # Replace with the agent ID for which you want to authorize and save credentials
    agent_id = "pY3bx5WFSTTkc0PNuBSA"

    # Call the authorization function
    authorize_and_save_credentials(agent_id)
