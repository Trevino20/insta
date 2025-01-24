import json
import requests
from flask import Flask, request, jsonify, render_template, session, redirect, url_for

app = Flask(__name__)
app.secret_key = "123"

@app.route("/")
def hello_world():
    return render_template('Welcome.html') 

@app.route("/privacy_policy")
def privacy_policy():
    with open("./privacy_policy.html", "rb") as file:
        privacy_policy_html = file.read()
    return privacy_policy_html

# Define the verify token
VERIFY_TOKEN = "123456"

@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    if request.method == "GET":
        hub_mode = request.args.get("hub.mode")
        hub_challenge = request.args.get("hub.challenge")
        hub_verify_token = request.args.get("hub.verify_token")

        # Validate the verify token
        if hub_verify_token == VERIFY_TOKEN:
            return hub_challenge  # Return the hub.challenge to confirm
        else:
            return "Forbidden", 403

    elif request.method == "POST":
        # Handle webhook POST requests here
        try:
            print(json.dumps(request.get_json(), indent=4))
        except Exception as e:
            print(f"Error: {e}")
        return "<p>POST request received</p>", 200
    
# =============== old method - Case 1 Login ================
@app.route('/loginpage')
def home():
    return render_template('login.html') 

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if username and password:
        session['username'] = username
        session['password'] = password
        return redirect(url_for('get_instagram_data'))     
    else:
        return jsonify({"message": "Invalid login data. Username and password are required."}), 400



with open('config.json', 'r') as json_file:
    config_data = json.load(json_file)
    
ig_user_id = config_data.get("ig_user_id", "N/A")
app_id = config_data.get("fapp_id", "N/A")
app_secret = config_data.get("fapp_secret", "N/A")
long_access_token = config_data.get("long_access_token", "N/A")



@app.route('/get_instagram_data')
def get_instagram_data():
    USERNAME = session.get('username', None)
    url = f"https://graph.facebook.com/v22.0/{ig_user_id}"
    params = {
        "fields": f"business_discovery.username({USERNAME}){{followers_count,media_count,media{{like_count}}}}",
        "access_token": long_access_token
    }

    response = requests.get(url, params=params)

    if response.status_code == 200:
        data = response.json().get("business_discovery", {})
        followers_count = data.get('followers_count', 'N/A')
        media_count = data.get('media_count', 'N/A')

        # Calculate average like count
        media_data = data.get('media', {}).get('data', [])
        like_counts = [media.get('like_count', 0) for media in media_data]
        avg_like_count = sum(like_counts) / len(like_counts) if like_counts else 0

        session['media_data'] = media_data
        session['like_counts'] = like_counts
        session['avg_like_count'] = avg_like_count
        return redirect(url_for('dashboard')) 
      
        # return jsonify({
        #     "followers_count": followers_count,
        #     "media_count": media_count,
        #     "average_like_count": avg_like_count
        # })
    else:
        return jsonify({"error": response.json()}), 400
# ------------------------------------Login page end----------------------------



# Set your secret key for session management
app.secret_key = 'your_secret_key'

# Read the config file
with open('config2.json', 'r') as json_file:
    config2_data = json.load(json_file)
    
app_id2 = config2_data.get("app_id", "N/A")  # Using config2_data
secret_id = config2_data.get("secret_id", "N/A")  # Using config2_data
redirect_uri = "https://a658-103-72-75-85.ngrok-free.app/your_insta_token"

# Renamed the function to avoid conflict
@app.route('/login2')
def login2():
    url = "https://www.instagram.com/oauth/authorize?"
    url += f"client_id={app_id2}"  # No need for int()
    url += f"&redirect_uri={redirect_uri}"
    url += "&response_type=code"
    url += "&scope=" + (
        "instagram_business_basic,instagram_business_content_publish,"
        "instagram_business_manage_messages,instagram_business_manage_comments"
    ).replace(",", "%2C")
    return redirect(url)

@app.route("/your_insta_token")
def your_insta_token():
    # Get authorization code from request params
    authorization_code = request.args.get("code")
    if not authorization_code:
        return "<p>Error: Missing authorization code.</p>"

    # Get access token
    url = "https://api.instagram.com/oauth/access_token"
    payload = {
        "client_id": app_id2,  # Using correct app ID from the config
        "client_secret": secret_id,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
        "code": authorization_code,
    }
    response = requests.post(url, data=payload)
    data = response.json()

    # Debugging: Print the response
    if 'access_token' not in data:
        return f"<p>Error: {data.get('error_message', 'Unexpected response')}. Response: {data}</p>"

    # Extract access token
    user_access_token = data["access_token"]
    session['user_access_token'] = user_access_token
    return redirect(url_for('get_user_info')) 
    
@app.route("/get_user_info")
def get_user_info():
    # Fetch long access token from session
    user_access_token = session.get("user_access_token")
    if not user_access_token:
        return "<p>Error: Access token is missing or expired.</p>"

    # Fetch user profile info
    url_user = "https://graph.instagram.com/v21.0/me"
    payload_user = {
        "fields": "id,username,name,account_type,profile_picture_url,followers_count,follows_count,media_count",
        "access_token": user_access_token,
    }
    response_user = requests.get(url_user, params=payload_user)
    user_data = response_user.json()

    # Handle API response for user profile
    if "error" in user_data:
        return f"<p>Error fetching user info: {user_data.get('error', {}).get('message', 'Unknown error')}</p>"

    # Fetch user's media data
    url_media = f"https://graph.instagram.com/v21.0/{user_data['id']}/media"
    payload_media = {
        "fields": "like_count",
        "access_token": user_access_token,
    }
    response_media = requests.get(url_media, params=payload_media)
    media_data = response_media.json()

    # Handle API response for media data
    if "error" in media_data:
        return f"<p>Error fetching media data: {media_data.get('error', {}).get('message', 'Unknown error')}</p>"

    # Calculate average like count
    media_items = media_data.get("data", [])
    if media_items:
        total_likes = sum(item.get("like_count", 0) for item in media_items)
        avg_like_count = total_likes / len(media_items)
    else:
        avg_like_count = 0

    # Display user and calculated information in an HTML response
    return f"""
    <h1>Instagram User Info</h1>
    <p><strong>ID:</strong> {user_data.get('id', 'N/A')}</p>
    <p><strong>Username:</strong> {user_data.get('username', 'N/A')}</p>
    <p><strong>Name:</strong> {user_data.get('name', 'N/A')}</p>
    <p><strong>Account Type:</strong> {user_data.get('account_type', 'N/A')}</p>
    <p><strong>Profile Picture:</strong> <img src="{user_data.get('profile_picture_url', '#')}" alt="Profile Picture" width="100"></p>
    <p><strong>Followers:</strong> {user_data.get('followers_count', 'N/A')}</p>
    <p><strong>Follows:</strong> {user_data.get('follows_count', 'N/A')}</p>
    <p><strong>Media Count:</strong> {user_data.get('media_count', 'N/A')}</p>
    <p><strong>Average Like Count:</strong> {avg_like_count:.2f}</p>
    """


    
    
@app.route('/dashboard')
def dashboard():
    # Get data from session
    media_data = session.get('media_data', None)
    like_counts = session.get('like_counts', None)
    avg_like_count = session.get('avg_like_count', None)
    return render_template('dashboard.html', media_data=media_data, like_counts=like_counts, avg_like_count=avg_like_count)

if __name__ == "__main__":
    app.run(debug=True)