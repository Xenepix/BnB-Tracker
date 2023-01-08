import json
import requests
from pprint import pprint


# Import vault
def get_keys():
    with open('../../vault/nordigen_keys.json') as f:
        credentials = json.load(f)
    return credentials


NORDIGEN_OBTAIN_TOKENS = "https://ob.nordigen.com/api/v2/token/new/"


# HEADERS = {'Content-Type': 'application/json',
#            'accept': 'application/json'}


# Get Nordigen token
def get_nordigen_token():
    """
    access_token_life: 24h
    refresh_token_life: 30d
    :return:
    """
    credentials = get_keys()
    response = requests.post(NORDIGEN_OBTAIN_TOKENS, data = credentials)
    with open('data/tokens.json', 'w') as f:
        json.dump(response.json(), f, indent = 4)
    return response.json().get('access'), response.json().get('refresh')


def read_auth_token():
    with open('data/tokens.json') as f:
        token = json.load(f)
    auth = {'Authorization': f'Bearer {token["access"]}'}
    return auth


def _country_banks_list(country: str):
    auth = read_auth_token()
    url = f"https://ob.nordigen.com/api/v2/institutions/?country={country}"
    response = requests.get(url, headers = auth)
    return response.json()


def _create_end_user(bank_id):
    auth = read_auth_token()
    url = "https://ob.nordigen.com/api/v2/agreements/enduser/"

    data = {'institution_id': bank_id,
            'max_historical_days': 30,
            'access_valid_for_days': 1,
            'access_scope': ['balances', 'details', "transactions"]}
    response = requests.post(url, headers = auth, data = data)
    return response.json()


def get_end_user_agreement(bank_name: str = 'N26 Bank'):
    banks = _country_banks_list('FR')
    for bank in banks:
        if bank.get('name') == bank_name:
            resp_json = _create_end_user(bank.get('id'))
            with open('data/end_user.json', 'w') as f:
                json.dump(resp_json, f, indent = 4)
            break


def create_link_user_bank(bank_id: str = "N26_NTSBDEB1"):
    with open('data/end_user.json', 'r') as f:
        end_user = json.load(f)
    auth = read_auth_token()
    url = "https://ob.nordigen.com/api/v2/requisitions/"
    data = {'redirect': 'https://www.google.com',
            'institution_id': bank_id,
            'reference': 'nico',
            'agreement': end_user['id'],
            'user_language': 'fr',
            "account_selection": False,
            "redirect_immediate": False
            }
    response = requests.post(url, headers = auth, data = data)
    with open('data/link.json', 'w') as f:
        json.dump(response.json(), f, indent = 4)
    return response.json()


def get_accounts():
    auth = read_auth_token()
    # get link id
    with open('data/link.json', 'r') as f:
        link = json.load(f)
    url = f"https://ob.nordigen.com/api/v2/requisitions/{link['id']}/"
    response = requests.get(url, headers = auth)
    return response.json()


def accounts():
    auth = read_auth_token()
    accounts = get_accounts().get("accounts")
    for account in accounts:
        url = f"https://ob.nordigen.com/api/v2/accounts/{account}/balances/"
        response = requests.get(url, headers = auth)
        pprint(response.json())


if __name__ == '__main__':
    # get_end_user_agreement()
    # create_link_user_bank()
    # accounts()

    banks = _country_banks_list('de')
    for bank in banks:
        print(bank.get("name"))
