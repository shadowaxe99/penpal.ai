import firebase_admin
from firebase_admin import credentials, firestore

def get_agents():
    db = firestore.client()

    # Query the AGENTS collection to get all document IDs and associated emails
    agents_info = []
    agents_collection = db.collection("AGENTS").stream()
    for doc in agents_collection:
        agent_id = doc.id
        agent_data = doc.to_dict()
        agent_email = agent_data.get("agentEmail")
        data = {
            "id": agent_id,
            "email": agent_email
        }
        agents_info.append(data)

    return agents_info


def get_associated_emails_for_agent(agent_id):
    db = firestore.client()

    # Initialize an empty result dictionary
    result = {}

    # Get a reference to the agent document
    agent_ref = db.collection("AGENTS").document(agent_id)

    # Query the subcollection "AssociatedUsers"
    associated_users_ref = agent_ref.collection("AssociatedUsers")
    associated_users_docs = associated_users_ref.stream()

    # Iterate through the documents in the subcollection
    for associated_user_doc in associated_users_docs:
        user_data = associated_user_doc.to_dict()

        user_id = user_data.get("userId")

        # Get the user document to fetch the defaultEmail
        user_ref = db.collection("USERS").document(user_id)
        user_doc = user_ref.get()

        if user_doc.exists:
            default_email = user_doc.get("defaultEmail")
            # print(f"Default email for user {user_id}: {default_email}")

            # Get the USERMAILS collection from the user document
            usermails_ref = user_ref.collection("USEREMAILS")
            usermails_docs = usermails_ref.stream()

            # Iterate through USERMAILS collection to fetch emails
            for usermail_doc in usermails_docs:
                email_data = usermail_doc.to_dict()
                email = email_data.get("email")

                # Add the email and defaultEmail to the result dictionary
                result[email] = [default_email, user_id]

    return result

if __name__ == "__main__":
    # Initialize Firebase Admin SDK
    cred = credentials.Certificate("firebaseCredentials.json")
    firebase_admin.initialize_app(cred)

    # Example usage:
    agents = get_agents()
    print(agents)

    agent_id = agents[0]["id"]
    email_dict = get_associated_emails_for_agent(agent_id)
    print(email_dict)
