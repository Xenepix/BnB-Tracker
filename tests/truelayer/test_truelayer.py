import requests
import json
from uuid import uuid4
from pprint import pprint
def get_tokens():
    with open('../../vault/truelayer_keys.json') as f:
        keys = json.load(f)
    url = "https://auth.truelayer-sandbox.com/connect/token"

    payload = {
        "grant_type": "authorization_code",
        "client_id": keys['client_id'],
        "client_secret": keys['client_secret'],
        "code": "69C5EEE28BAD83066F52D1717CAA6F886670D5B3C54DA83DB1A4B86382535E1B",
        "redirect_uri": "https://console.truelayer.com/redirect-page"
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }

    response = requests.post(url, json = payload, headers = headers)
    with open('data/tokens.json', 'w') as f:
        json.dump(response.json(), f, indent = 4)
    # Save token
    return response.json()

def load_tokens():
    with open('data/tokens.json') as f:
        tokens = json.load(f)
    return tokens.get('access_token'), tokens.get('refresh_token')

def generate_link():
    with open('../../vault/truelayer_keys.json') as f:
        keys = json.load(f)
    url = "https://auth.truelayer-sandbox.com/v1/authuri"
    credentials = get_tokens().get("access_token")
    payload = {
        "response_type": "code",
        "code": credentials,
        "code_challenge_method": "S256",
        "response_mode": "form_post",
        "client_id": keys['client_id'],
        "redirect_uri": "https://console.truelayer.com/redirect-page",
        "scope": "info accounts balance",
        "state": str(uuid4()),
        "consent_id": str(uuid4()),
        "provider_id": str(uuid4()),
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }


    response = requests.post(url, json = payload, headers = headers)
    res = response.json()

    # res["state"] = payload["state"]
    # res["consent_id"] = payload["consent_id"]
    # res["provider_id"] = payload["provider_id"]
    with open('data/link.json', 'w') as f:
        json.dump(res, f, indent = 4)
    return res

if __name__ == '__main__':
    # res = get_tokens()
    # print(res)
    # get_tokens()
    url = "https://api.truelayer-sandbox.com/data/v1/accounts?async=false"

    headers = {"accept": "application/json",
               "authorization": f"Bearer {load_tokens()[0]}",}

    response = requests.get(url, headers = headers)
    print(response)
    pprint(response.json())