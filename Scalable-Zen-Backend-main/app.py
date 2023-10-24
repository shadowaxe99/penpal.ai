from flask import Flask, request, url_for, redirect, session
from flask_cors import CORS
from list_emails import get_agents, get_associated_emails_for_agent
import firebase_admin
from firebase_admin import credentials, firestore
from read_threads import get_unread_threads_and_service
import re, base64, time
from calendar_api import fetch_free_time, create_calendar_event
from responder import generate_resp
from event_planner import extract_meeting_info
from gmail_api import reply_to_email_thread, send_email
from datetime import datetime
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import logging

import os
# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = "secret key"
CORS(app)

cred = credentials.Certificate("firebaseCredentials.json")
firebase_admin.initialize_app(cred)

#ADDING MESSAGES TO THREAD COLLECTION
def extract_email_content(message, new = False):
    current_datetime = datetime.now()
    formatted_date = current_datetime.strftime("%d/%m/%Y %H:%M:%S")
    # Initialize email content
    email_content = {
        "bcc": message.get('bccRecipients', []),
        "cc": message.get('ccRecipients', []),
        "sender": '',
        "receiver": '',
        "body": '',
        "subject": '',
        "timestamp": formatted_date,
    }

    # Extract email addresses from headers
    for header in message['payload']['headers']:
        if header['name'].lower() == 'from':
            email_content["sender"] = extract_email(header['value'])
        elif header['name'].lower() == 'to':
            email_content["receiver"] = extract_email(header['value'])
        elif header['name'].lower() == 'cc':
            email_content["cc"] = extract_email(header['value'])
        elif header['name'].lower() == 'bcc':
            email_content["bcc"] = extract_email(header['value'])
        elif header['name'].lower() == 'subject':
            email_content["subject"] = header['value']

    # Check if 'parts' are available
    if 'parts' in message['payload']:
        # Initialize email body
        email_body = ''

        # Iterate through payload parts to find 'text/plain' part
        for part in message['payload']['parts']:
            if part['mimeType'] == 'text/plain':
                # Decode the base64 content (if it's base64 encoded)
                body_data = part['body'].get('data', '')
                if body_data:
                    part_body = base64.urlsafe_b64decode(body_data).decode('utf-8', 'ignore')
                    # Remove quoted text and everything after it
                    # if new:
                    #     email_body += part_body
                    # else:
                    email_body += re.sub(r'On [^\n]*wrote:[^\n]*\n[\s\S]*', '', part_body)

        email_content["body"] = email_body

    # If 'parts' are not available, use 'data' from 'body' directly
    if not email_content["body"]:
        body_data = message['payload']['body'].get('data', '')
        if body_data:
            email_content["body"] = base64.urlsafe_b64decode(body_data).decode('utf-8', 'ignore')

    return email_content
def add_message_to_thread(thread_ref, message, new = False):
    messages_collection = thread_ref.collection("MESSAGES")
    message_id = message['id']  # Assuming 'id' contains the message ID

    email_content = extract_email_content(message, new)

    message_ref = messages_collection.document(message_id)
    message_ref.set(email_content)

def add_message_to_user_threads(db, user_id, message, thread_id, message_id):
    # Navigate to the user's document
    user_ref = db.collection("USERS").document(user_id)
    threads_collection = user_ref.collection("THREADS")
    thread_ref = threads_collection.document(thread_id)
    messages_collection = thread_ref.collection("MESSAGES")
    email_content = extract_email_content(message)
    message_ref = messages_collection.document(message_id)
    
    message_ref.set(email_content)

#EXTRACTING EMAIL FROM A STRING
def extract_email(email_string):
    """
    Extracts email address from the provided string using a regular expression.
    """
    # Extract the email from the string
    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', email_string)
    if match:
        return match.group(0)
    return None

#EXTRACTING EMAIL FROM A THREAD
def get_emails_from_thread(messages, assistant_email, all_owners):
    print("GETTING EMAIL IDs FROM THREAD")
    all_emails = []

    for message in messages:
        from_email_list = [header['value'] for header in message['payload']['headers'] if header['name'].lower() == 'from']
        to_email_list = [header['value'] for header in message['payload']['headers'] if header['name'].lower() == 'to']
        cc_email_list = [header['value'] for header in message['payload']['headers'] if header['name'].lower() == 'cc']
        bcc_email_list = [header['value'] for header in message['payload']['headers'] if header['name'].lower() == 'bcc']
        
        all_emails.extend(from_email_list + to_email_list + cc_email_list + bcc_email_list)
    
    all_emails = list(set(all_emails))
    all_emails = [extract_email(email) for email in all_emails]
    
    print("All Emails: ", all_emails)
    print("All Owners: ", all_owners)
    owner_emails = [email for email in all_emails if email in all_owners and email != assistant_email]
    owner_email = owner_emails[0] if owner_emails else None

    client_emails = [email for email in all_emails if email != owner_email and email != assistant_email]
    client_email = client_emails[0] if client_emails else None

    return owner_email, client_email

#MARKING THREAD AS READ
def mark_thread_as_read(gmail_service, thread_id):
    gmail_service.users().threads().modify(
        userId='me',
        id=thread_id,
        body={'removeLabelIds': ['UNREAD']}
    ).execute()
    return "Thread marked as read."


@app.route('/')
def index():
    agents = get_agents()
    current_datetime = datetime.now()
    formatted_date = current_datetime.strftime("%d/%m/%Y %H:%M:%S")
    db = firestore.client()
    for agent in agents:
        agent_id = agent["id"]
        agent_email = agent["email"]
        print(f"Agent ID: {agent_id}, Agent Email: {agent_email}")

        emails = get_associated_emails_for_agent(agent_id)
        print(f"Associated Emails with Owner id: {emails}")
        email_ids = list(emails.keys())
        print(f"Associated Email IDs: {email_ids}")

        unread_threads, gmail_service = get_unread_threads_and_service(agent_id)
        print(f"Unread Threads: {len(unread_threads)}, Threads: {unread_threads}")
        if len(unread_threads) == 0:
            print("No unread threads found. Continuing...")
            continue

        for thread in unread_threads:
            thread_id = thread["id"]
            full_thread = gmail_service.users().threads().get(userId='me', id=thread['id']).execute()
            messages = full_thread.get('messages', [])
            owner_email, client_email = get_emails_from_thread(messages, agent_email, email_ids)

            if not owner_email:
                print("Owner email not found in thread. Marking it as read and continuing...")
                mark_thread_as_read(gmail_service, thread_id)
                continue
            if not client_email:
                print("Client email not found in thread. Marking it as read and continuing...")
                mark_thread_as_read(gmail_service, thread_id)
                continue
            
            print(f"Owner Email: {owner_email}, Client Email: {client_email}")
            user_id = emails[owner_email][1]
            user_ref = db.collection("USERS").document(user_id)
            status = user_ref.get().get("status")
            if status == "NoCal":
                print("User has not connected calendar. Sending email to connect calendar.")
                subject_reply = "Request to connect calendar"
                body_reply = "You have not connected your calendar yet. Please connect your calendar to use Zen."
                try:
                    reply_to_email_thread(gmail_service, messages[-1], body_reply, owner_email, thread['id'], agent_email)
                except Exception as e:
                    print("Error sending email: ", e)
                    logging.info("Error sending email: ", e)
                    send_email(gmail_service, owner_email, subject_reply, body_reply)
                mark_thread_as_read(gmail_service, thread_id)
                continue

            thread_ref = db.collection("THREADS").document(thread_id)
            thread_doc = thread_ref.get()

            if thread_doc.exists:
                print(f"Thread {thread_id} already exists in collection 'THREADS'")
                print(f"Adding last message- {messages[-1]['id']} to collection 'MESSAGES'")
                last_message = messages[-1]
                add_message_to_thread(thread_ref, last_message)

                print("ADDING THREAD TO USER's THREAD COLLECTION")
                add_message_to_user_threads(db, user_id, last_message, thread_id, last_message['id'])

                #FETCHING FREE TIME FOR OWNER
                userId = emails[owner_email][1]
                free_time, calendar_service, timeZone = fetch_free_time(userId)
                print(f"Free Time: {free_time}")

                messages_collection = thread_ref.collection("MESSAGES")
                all_messages = messages_collection.stream()
                history = ""
                for i, message in enumerate(all_messages):
                    message_data = message.to_dict()
                    history += f"{message_data['sender']}: {message_data['body']}\n"
                print("History: ", history)

                body_reply, subject_reply = generate_resp(history, client_email, owner_email, free_time, agent_email)
                print("Body Reply: ", body_reply)
                print("Subject Reply: ", subject_reply)

                meeting_info = extract_meeting_info(body_reply)
                if meeting_info.meet:
                    print("MEETING CONFIRMED")
                    start_time = meeting_info.startTime
                    end_time = meeting_info.endTime
                    print("START TIME: {}".format(start_time))
                    print("END TIME: {}".format(end_time))
                    print("TIME ZONE: {}".format(timeZone))
                    event = create_calendar_event(calendar_service, owner_email, client_email, agent_email, start_time, end_time, timeZone)
                    try:
                        meeting_link = event.get('hangoutLink', None)
                    except:
                        meeting_link = ""
                    body_reply += "\n\nMeeting scheduled for {} to {} GMT \n {}".format(start_time, end_time, meeting_link)

                    # ADD MEETING TO MEETINGS COLLECTION
                    meetings_ref = db.collection("MEETINGS")
                    meeting_id = meetings_ref.document()
                    meeting_data = {
                        "startTime": start_time,
                        "endTime": end_time,
                        "timeZone": timeZone,
                        "meetingLink": meeting_link,
                        "lastAgentAction": formatted_date,
                        "participants": [owner_email, client_email],
                        "schedulingAgentId": agent_id,
                        "schedulingAgentEmail": agent_email,
                        "threadId": thread_id,
                        "userId": userId,
                    }
                    meeting_id.set(meeting_data)
                    print("MEETING ADDED TO MEETINGS COLLECTION")

                    #CHANGE STATUS FOR THREAD
                    thread_ref.update({"status": "Scheduled"})
                    thread_ref.update({"meetingId": meeting_id})
                    print("THREAD STATUS CHANGED TO SCHEDULED")

                    #ADD MEETING IN USER COLLECTION
                    users_ref = db.collection("USERS")
                    user_doc_ref = users_ref.document(userId)
                    meetings_collection_ref = user_doc_ref.collection("MEETINGS")
                    new_meeting_ref = meetings_collection_ref.document()
                    meeting_data = {
                        "meetingId": meeting_id,
                        "meetingLink": meeting_link,
                    }
                    new_meeting_ref.set(meeting_data)
                    print(f"MEETING ADDED TO USER {userId}', COLLECTION")

                sent_message = reply_to_email_thread(gmail_service, last_message, body_reply, client_email, thread['id'], owner_email)
                message_id = sent_message['id']
                sent_message = gmail_service.users().messages().get(userId='me', id=sent_message['id']).execute()
                add_message_to_thread(thread_ref, sent_message)
                print("REPLY SENT AND ADDED TO THREAD: ", thread_id)

                add_message_to_user_threads(db, userId, sent_message, thread_id, message_id)
                print("REPLY SENT AND ADDED TO USER's THREAD: ", thread_id)

                mark_thread_as_read(gmail_service, thread_id)
                print(f"Marked thread {thread_id} as read.")


            else:
                print(f"Thread {thread_id} does not exist in collection 'THREADS'")
                print("Adding thread to collection 'RECEIVEDEMAILS'")
                incoming_data = {
                    "ownerEmail": owner_email,
                    "ownerId": emails[owner_email][1],
                    "associatedClientEmail": client_email,
                    "handlingAgentId": agent_id,
                    "subject": messages[0]['payload']['headers'][0]['value'],
                    "createdAt": formatted_date,
                    "associatedThreadId": thread_id,
                }
                received_emails_ref = db.collection("RECEIVEDEMAILS").document(thread_id)
                received_emails_ref.set(incoming_data)

                for message in messages:
                    add_message_to_thread(received_emails_ref, message, new = True)
                print("Added thread to collection 'RECEIVEDEMAILS'.")

                userId = emails[owner_email][1]
                free_time, calendar_service, timeZone = fetch_free_time(userId)
                print(f"Free Time: {free_time}")

                messages_collection = received_emails_ref.collection("MESSAGES")
                all_messages = messages_collection.stream()
                history = ""
                for i, message in enumerate(all_messages):
                    message_data = message.to_dict()
                    history += f"{message_data['sender']}: {message_data['body']}\n"
                print("History: ", history)

                body_reply, subject_reply = generate_resp(history, client_email, owner_email, free_time, agent_email)
                print("Body Reply: ", body_reply)
                print("Subject Reply: ", subject_reply)

                meeting_info = extract_meeting_info(body_reply)
                status = "Not Scheduled"
                meeting_id = ""
                meeting_link = ""
                if meeting_info.meet:
                    print("MEETING CONFIRMED")
                    start_time = meeting_info.startTime
                    end_time = meeting_info.endTime
                    print("START TIME: {}".format(start_time))
                    print("END TIME: {}".format(end_time))
                    print("TIME ZONE: {}".format(timeZone))
                    event = create_calendar_event(calendar_service, owner_email, client_email, agent_email, start_time, end_time, timeZone)
                    try:
                        meeting_link = event.get('hangoutLink', None)
                    except:
                        meeting_link = ""
                    body_reply += "\n\nMeeting scheduled for {} to {} GMT \n {}".format(start_time, end_time, meeting_link)

                    # ADD MEETING TO MEETINGS COLLECTION
                    meetings_ref = db.collection("MEETINGS")
                    meeting_id = meetings_ref.document()
                    meeting_data = {
                        "startTime": start_time,
                        "endTime": end_time,
                        "timeZone": timeZone,
                        "meetingLink": meeting_link,
                        "lastAgentAction": formatted_date,
                        "participants": [owner_email, client_email],
                        "schedulingAgentId": agent_id,
                        "schedulingAgentEmail": agent_email,
                        "userId": userId,
                    }
                    meeting_id.set(meeting_data)
                    print("MEETING ADDED TO MEETINGS COLLECTION")

                    #ADD MEETING IN USER COLLECTION
                    users_ref = db.collection("USERS")
                    user_doc_ref = users_ref.document(userId)
                    meetings_collection_ref = user_doc_ref.collection("MEETINGS")
                    new_meeting_ref = meetings_collection_ref.document()
                    meeting_data = {
                        "meetingId": meeting_id,
                        "meetingLink": meeting_link,
                    }
                    new_meeting_ref.set(meeting_data)
                    print(f"MEETING ADDED TO USER {userId}', COLLECTION")

                sent_message = send_email(gmail_service, client_email, subject_reply, body_reply, owner_email)
                new_thread_id = sent_message['threadId']
                new_message_id = sent_message['id']
                new_thread_ref = db.collection("THREADS").document(new_thread_id)
                new_thread_data = {
                    "ownerEmail": owner_email,
                    "ownerId": emails[owner_email][1],
                    "associatedClientEmail": client_email,
                    "handlingAgentId": agent_id,
                    "subject": subject_reply,
                    "createdAt": formatted_date,
                    "status": status,
                    "meetingId": meeting_id,
                }
                #ADDING NEW THREAD TO THREADS COLLECTION
                new_thread_ref.set(new_thread_data)

                print("ADDING LAST MESSAGE TO THREAD")
                sent_message = gmail_service.users().messages().get(userId='me', id=sent_message['id']).execute()
                add_message_to_thread(new_thread_ref, sent_message)
                print("EMAIL SENT AND ADDED TO THREAD: ", thread_id)

                #UPDATING STATUS OF THREAD
                if meeting_info.meet:
                    new_thread_ref.update({"status": "Scheduled"})
                    new_thread_ref.update({"meetingId": meeting_id})

                #ASSOCIATING THREAD WITH RECEIVED EMAIL
                received_emails_ref.update({"associatedThreadId": new_thread_id})

                print("ADDING THREAD TO USER's COLLECTION")
                users_ref = db.collection("USERS")
                user_doc_ref = users_ref.document(userId)
                user_threads_collection_ref = user_doc_ref.collection("THREADS")
                new_thread_ref = user_threads_collection_ref.document(new_thread_id)
                new_thread_ref.set(new_thread_data)


                add_message_to_user_threads(db, userId, sent_message, new_thread_id, new_message_id)
                print("REPLY SENT AND ADDED TO USER's THREAD: ", thread_id)

                mark_thread_as_read(gmail_service, thread_id)
                print(f"Marked thread {thread_id} as read.")
    return "Success"

@app.route('/authenticate_calendar', methods=['POST', 'GET'])
def authenticate():
    user_id = request.args.get('userId')
    print("USER ID: ", user_id)
    logging.info("USER ID: ", user_id)
    flow = InstalledAppFlow.from_client_secrets_file(
        'servicesCredentials.json',
        ['https://www.googleapis.com/auth/calendar']
    )
    # flow.redirect_uri = url_for('callback', _external=True)
    flow.redirect_uri = "https://zenbackend-mw5cw3u7ga-uc.a.run.app/callback"
    print(flow.redirect_uri)
    logging.info("Redirect URI: ", flow.redirect_uri)
    authorization_url, _ = flow.authorization_url(prompt='consent')
    session['userId'] = user_id
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    print("SESSION: ", session)
    logging.info("SESSION: ", session)
    userId = session.get("userId")
    print("USER ID IN CALLBACK: ", userId)
    logging.info("USER ID IN CALLBACK: ", userId)
    flow = InstalledAppFlow.from_client_secrets_file(
        'servicesCredentials.json',
        ['https://www.googleapis.com/auth/calendar']
    )
    # flow.redirect_uri = url_for('callback', _external=True)
    flow.redirect_uri = "https://zenbackend-mw5cw3u7ga-uc.a.run.app/callback"
    print(flow.redirect_uri)
    authorization_response = request.url.replace("http://", "https://")
    flow.fetch_token(authorization_response=authorization_response)

    # Get the user's email
    service = build('calendar', 'v3', credentials=flow.credentials)
    profile = service.calendarList().get(calendarId='primary').execute()
    email = profile['id']

    # Serialize credentials
    serialized_credentials = {
        'token': flow.credentials.token,
        'refresh_token': flow.credentials.refresh_token,
        'token_uri': flow.credentials.token_uri,
        'client_id': flow.credentials.client_id,
        'client_secret': flow.credentials.client_secret,
        'scopes': flow.credentials.scopes
    }
    print("SERIALIZED CREDENTIALS: ", serialized_credentials)
    logging.info("SERIALIZED CREDENTIALS: ", serialized_credentials)

    # Prepare data for Firestore
    user_data = {
        'calendarCredentials': serialized_credentials,
        'calendarEmail': email,
        'status': 'CalConnected-Active'
    }

    db = firestore.client()
    users_ref = db.collection(u'USERS')
    user_doc = users_ref.document(userId)

    user_doc.update(user_data)
    print("USER DATA UPDATED FOR USER: ", userId)
    logging.info("USER DATA UPDATED FOR USER: ", userId)

    return redirect("https://zen-scheduler-web.vercel.app/dashboard")

port = int(os.environ.get("PORT", 8080))
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=True)