from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

def get_gmail_services():
    # Load or authorize Gmail credentials
    gmail_creds = None
    gmail_scopes = ['https://www.googleapis.com/auth/gmail.modify']

    if gmail_creds and not gmail_creds.valid:
        if gmail_creds.expired and gmail_creds.refresh_token:
            gmail_creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', gmail_scopes)
        gmail_creds = flow.run_local_server(port=0)
        with open('gmail_token.json', 'w') as token:
            token.write(gmail_creds.to_json())

    gmail_service = build('gmail', 'v1', credentials=gmail_creds)

    # Fetch the user's email address
    user_info = gmail_service.users().getProfile(userId='me').execute()
    email_address = user_info.get('emailAddress', '')

    # Save the email address to assistant_email.txt
    with open('assistant_email.txt', 'w') as email_file:
        email_file.write(email_address)

    return gmail_service

def get_calendar_service():
    # Load or authorize Calendar credentials
    calendar_creds = None
    calendar_scopes = ['https://www.googleapis.com/auth/calendar']

    # Check if we have existing credentials
    try:
        with open('calendar_token.json', 'r') as token:
            calendar_creds = token.read()
    except FileNotFoundError:
        # No existing credentials found
        pass

    if calendar_creds and not calendar_creds.valid:
        if calendar_creds.expired and calendar_creds.refresh_token:
            calendar_creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', calendar_scopes)
        calendar_creds = flow.run_local_server(port=0)
        with open('calendar_token.json', 'w') as token:
            token.write(calendar_creds.to_json())

    calendar_service = build('calendar', 'v3', credentials=calendar_creds)

    return calendar_service

if __name__ == "__main__":
    get_gmail_services()
    get_calendar_service()