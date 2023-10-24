from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from datetime import datetime, timedelta
import pytz
import json
import pickle
import firebase_admin
from firebase_admin import credentials, storage
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import json
from cryptography.fernet import Fernet
from uuid import uuid4
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import firebase_admin
from firebase_admin import credentials, firestore
from pytz import timezone

def filter_weekends(response: str) -> str:
    lines = response.strip().split("\n")
    filtered_lines = []
    for line in lines:
        if "," not in line:  # Check if the line contains a comma
            filtered_lines.append(line)
            continue
        try:
            date_str = line.split(",")[1].strip().split(":")[0]
            date = datetime.strptime(date_str, "%d %B %Y")
            if date.weekday() not in [5, 6]:
                filtered_lines.append(line)
        except ValueError:
            print(f"Error parsing date from line: {line}")  # Debug print
            filtered_lines.append(line)
    return "\n".join(filtered_lines)

def build_calendar_service(user_credentials):
    try:
        creds = Credentials.from_authorized_user_info(user_credentials)
        service = build("calendar", "v3", credentials=creds)
        return service
    except Exception as e:
        print(f"Error building Calendar service: {e}")
        return None

def fetch_free_time(userId):
    db = firestore.client()

    # Retrieve user's document from the USERS collection
    user_ref = db.collection("USERS").document(userId)
    user_doc = user_ref.get()

    if not user_doc.exists:
        return []  # User document does not exist

    # Retrieve user's preferences and calendar credentials
    preferences = user_doc.get("preferences")
    calendar_token = user_doc.get("calendarCredentials")
    email_address = user_doc.get("defaultEmail")
    calendar_email = user_doc.get("calendarEmail")

    print(f"Preferences: {preferences}")
    print(f"Calendar Credentials: {calendar_token}")
    print(f"Email Address: {email_address}")
    print(f"Calendar Email: {calendar_email}")
    # return "YOU ARE FREE FOR NEXT 20 DAYS", "Success", "Success"
    
    calendar_service = build_calendar_service(calendar_token)
    calendar_timezone = get_calendar_timezone(calendar_email, calendar_service)

    # Fetch the free/busy information
    preferred_start_time = preferences['startTime']
    preferred_end_time = preferences['endTime']
    preferred_start_time_dt = datetime.strptime(preferences['startTime'], '%H:%M').time()
    preferred_end_time_dt = datetime.strptime(preferences['endTime'], '%H:%M').time()
    tz = timezone(calendar_timezone)
    now = datetime.utcnow().replace(tzinfo=timezone('UTC')).astimezone(tz)
    end_time = now + timedelta(days=20)
    body = {
        "timeMin": now.isoformat(),
        "timeMax": end_time.isoformat(),
        "items": [{"id": email_address}]
    }
    free_busy_response = calendar_service.freebusy().query(body=body).execute()

    # Extract the busy times
    busy_times = free_busy_response['calendars'][email_address]['busy']

    # Check if there are no upcoming events
    if not busy_times:
        resp = f"You are free for the next 20 days between {preferred_start_time} and {preferred_end_time}. (Time Zone: {calendar_timezone})"
        return resp, calendar_service, calendar_timezone

    # Adjust the start time to the nearest half-hour mark
    while now.minute % 30 != 0:
        now += timedelta(minutes=1)

    # Initialize all days with full free slots within the preferred time range
    all_days = {}
    if now.time() < datetime.strptime("8:30", '%H:%M').time():
        start_day = 0
    else:
        start_day = 1
        # Handle the current day
        current_day_slots = []
        now += timedelta(hours=2)
        while now.minute % 30 != 0:
            now += timedelta(minutes=1)
        if preferred_start_time_dt <= now.time() <= preferred_end_time_dt:
            current_day_slots.append((now, datetime.combine(now.date(), preferred_end_time_dt).astimezone(tz)))
        if current_day_slots:
            all_days[now] = current_day_slots
        else:
            start_day = 0
    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)

    for day_offset in range(start_day, 20):  # 20 days
        # Create a timezone-aware datetime for the start of the day
        tz_aware_start_of_day = (start_of_day + timedelta(days=day_offset)).astimezone(tz)

        # Combine the timezone-aware datetime with the preferred times
        preferred_start_of_day = tz_aware_start_of_day.replace(hour=preferred_start_time_dt.hour, minute=preferred_start_time_dt.minute)
        preferred_end_of_day = tz_aware_start_of_day.replace(hour=preferred_end_time_dt.hour, minute=preferred_end_time_dt.minute)
        
        all_days[tz_aware_start_of_day] = [(preferred_start_of_day, preferred_end_of_day)]


    # Remove busy slots from the all_days dictionary
    for busy in busy_times:
        busy_start = datetime.fromisoformat(busy['start'][:-1]).replace(tzinfo=timezone('UTC')).astimezone(tz)
        busy_end = datetime.fromisoformat(busy['end'][:-1]).replace(tzinfo=timezone('UTC')).astimezone(tz)

        day_of_busy_start = busy_start.replace(hour=0, minute=0, second=0, microsecond=0)

        if day_of_busy_start in all_days:
            new_slots = []
            for slot in all_days[day_of_busy_start]:
                # If busy time overlaps with this slot, split or adjust the slot
                if slot[0] < busy_end and slot[1] > busy_start:
                    if slot[0] < busy_start:
                        new_slots.append((slot[0], busy_start))
                    if slot[1] > busy_end:
                        new_slots.append((busy_end, slot[1]))
                else:
                    new_slots.append(slot)
            all_days[day_of_busy_start] = new_slots

    # Format the free slots
    formatted_free_slots = []
    for day, slots in all_days.items():
        formatted_day = day.strftime('%A, %d %B %Y')
        if len(slots) == 1 and slots[0][0] == datetime.combine(day.date(), preferred_start_time_dt).astimezone(tz) and slots[0][1] == datetime.combine(day.date(), preferred_end_time_dt).astimezone(tz):
            time_ranges = f"{slots[0][0].strftime('%I:%M %p')} - {slots[0][1].strftime('%I:%M %p')}"
            formatted_free_slots.append(f"{formatted_day}: {time_ranges}")
        else:
            time_ranges = [f"{slot[0].strftime('%I:%M %p')} - {slot[1].strftime('%I:%M %p')}" for slot in slots]
            formatted_time_ranges = ', '.join(time_ranges)
            formatted_free_slots.append(f"{formatted_day}: {formatted_time_ranges}")

    total_free_slots = '\n'.join(formatted_free_slots) + f"\n(Time Zone: {calendar_timezone})"
    if not preferences['yesWeekends']:
        total_free_slots = filter_weekends(total_free_slots)
    return total_free_slots, calendar_service, calendar_timezone




def create_calendar_event(owner_calendar_service, owner_email, client_email, assistant_email, start_time, end_time, time_zone = 'US/Eastern'):
    # Get the calendar service for the owner
    # if not owner_calendar_service:
    #     owner_calendar_service = get_calendar_service(owner_email)

    # Define event details
    event = {
        "summary": "Meeting with {}".format(client_email),
        "start": {"dateTime": start_time, "timeZone": time_zone},
        "end": {"dateTime": end_time, "timeZone": time_zone},
        "attendees": [{"email": owner_email}, {"email": client_email}],
        "organizer": {"email": assistant_email},
        "conferenceData": {
            "createRequest": {
                "requestId": uuid4().hex,
                "conferenceSolutionKey": {"type": "hangoutsMeet"}
            }
        },
        "reminders": {"useDefault": True}
    }

    # Insert the event into the owner's calendar
    try:
        event = owner_calendar_service.events().insert(calendarId="primary", sendNotifications=True, body=event, conferenceDataVersion=1).execute()
        return event
    except Exception as e:
        return f"Error creating event: {str(e)}"

def get_calendar_timezone(email_address, service = None):
    if not service:
        service = get_calendar_service(email_address)
    calendar_metadata = service.calendars().get(calendarId=email_address).execute()
    return calendar_metadata['timeZone']

if __name__ == '__main__':
    # Initialize Firebase Admin SDK
    cred = credentials.Certificate("firebaseCredentials.json")
    firebase_admin.initialize_app(cred)

    service = get_calendar_service(dummy_email)
    print(get_calendar_timezone(dummy_email, service))
    print(fetch_free_time(dummy_email))
