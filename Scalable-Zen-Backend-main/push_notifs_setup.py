import pickle
import os.path
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from datetime import datetime

# Load credentials or generate them if they don't exist
with open('gmail_service.pkl', 'rb') as f:
    service = pickle.load(f)
# Build the service object

def stop_mailbox_updates(gmail_service):
    try:
        gmail_service.users().stop(userId='me').execute()
        print("Successfully stopped mailbox updates.")
    except Exception as e:
        print(f"An error occurred: {e}")
stop_mailbox_updates(service)
# Create the watch request
request = {
    'labelIds': ['UNREAD'],
    'topicName': 'projects/userbot-285810/topics/CheckNewEmail',
    'labelFilterBehavior': 'INCLUDE'
}

# # Execute the watch request
# response = service.users().watch(userId='me', body=request).execute()
# print(response)
