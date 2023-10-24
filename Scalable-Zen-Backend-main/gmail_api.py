from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from bs4 import BeautifulSoup
import base64
from datetime import datetime
import time
from email.mime.text import MIMEText
import copy, email


def read_threads(service):
    query = 'is:unread'
    results = service.users().threads().list(userId='me', q=query).execute()
    threads = results.get('threads', [])
    return threads


def read_emails(service):
    query = 'is:unread'
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    return messages

def data_encoder(text):
    if text and len(text)>0:
        message = base64.urlsafe_b64decode(text.encode('UTF8'))
        message = str(message, 'utf-8')
        message = email.message_from_string(message)
        return message
    else:
        return None

def get_message_text(msg):
    if msg.get('payload').get('parts', None):
        parts = msg.get('payload').get('parts', None)
        sub_part = copy.deepcopy(parts[0])
        while sub_part.get("mimeType", None) != "text/plain":
            try:
                sub_part = copy.deepcopy(sub_part.get('parts', None)[0])
            except Exception as e:
                break
        return data_encoder(sub_part.get('body', None).get('data', None)).as_string()
    else:
        return msg.get("snippet")

# Initialize the Gmail API

def get_gmail_service():
    creds = None
    if creds and not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file('gmail_credentials.json', ['https://www.googleapis.com/auth/gmail.modify'])
        creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)


# Function to send emails

def send_email(service, to_email, subject, body, bcc_email = None):
    email_msg = MIMEText(body)
    email_msg['to'] = to_email
    email_msg['subject'] = subject

    if bcc_email:
        email_msg['bcc'] = bcc_email

    raw_email = base64.urlsafe_b64encode(email_msg.as_bytes()).decode('utf-8')
    return service.users().messages().send(userId='me', body={'raw': raw_email}).execute()


def reply_to_email(service, original_message, reply_content):
    headers = original_message['payload']['headers']
    subject = next(header['value'] for header in headers if header['name'] == 'Subject')
    message_id = next(header['value'] for header in headers if header['name'] == 'Message-ID')
    references = next((header['value'] for header in headers if header['name'] == 'References'), None)

    raw_email = (
        f'Subject: {subject}\n'
        f'In-Reply-To: {message_id}\n'
        f'References: {references if references else message_id}\n'
        f'\n'
        f'{reply_content}\n'
    ).encode('utf-8')

    message = {
        'raw': base64.urlsafe_b64encode(raw_email).decode('utf-8')
    }

    service.users().messages().send(userId='me', body=message).execute()

def reply_to_email_thread(gmail_service, original_message, reply_text, to_email, thread_id, bcc_email=None):
    # Extract necessary headers from the original email
    original_headers = original_message['payload']['headers']
    message_id = next(header['value'] for header in original_headers if header['name'] == 'Message-ID')
    references = next((header['value'] for header in original_headers if header['name'] == 'References'), '')
    subject = next(header['value'] for header in original_headers if header['name'] == 'Subject')

    # Create the reply email
    message = MIMEText(reply_text)
    message['to'] = to_email
    if bcc_email:
        message['bcc'] = bcc_email
    message['subject'] = subject if subject.startswith('Re:') else 'Re: ' + subject
    message['in-reply-to'] = message_id
    message['references'] = message_id

    # Encode the message and send
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
    print("THREAD ID: {}".format(thread_id))

    return gmail_service.users().messages().send(userId='me', body={'raw': raw, 'threadId': thread_id}).execute()