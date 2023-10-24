import firebase_admin
from firebase_admin import credentials, firestore
import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from list_emails import get_agents

def build_gmail_service(credentials):
    try:
        creds = Credentials.from_authorized_user_info(credentials)
        service = build("gmail", "v1", credentials=creds)
        return service
    except Exception as e:
        print(f"Error building Gmail service: {e}")
        return None

def get_unread_threads_and_service(agent_id):
    db = firestore.client()

    # Get the agent document
    agent_ref = db.collection("AGENTS").document(agent_id)
    agent_doc = agent_ref.get()

    if not agent_doc.exists:
        return []  # Agent document does not exist

    # Retrieve the 'gmailToken' from the agent's document
    gmail_token = agent_doc.get("gmailToken")

    if gmail_token:
        # Build the Gmail service using the token
        gmail_service = build_gmail_service(gmail_token)

        if gmail_service:
            try:
                # List unread threads in the inbox
                results = gmail_service.users().threads().list(userId="me", q="is:unread in:inbox").execute()
                threads = results.get("threads", [])
                return threads, gmail_service
            except HttpError as error:
                print(f"Error listing unread threads: {error}")
                return [], gmail_service
    else:
        print("No Gmail token found in the agent's document.")
        return []

if __name__ == "__main__":
    # Initialize Firebase Admin SDK
    cred = credentials.Certificate("firebaseCredentials.json")
    firebase_admin.initialize_app(cred)

    # Call the function to process all agents and retrieve unread threads
    agent_ids = get_agents()
    for agent_id in agent_ids:
        unread_threads, service = get_unread_threads_and_service(agent_id)
        print(f"Agent ID: {agent_id}, Unread Threads: {len(unread_threads)}, Threads: {unread_threads}")
