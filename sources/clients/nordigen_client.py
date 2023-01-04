import requests
from copy import copy
import json

from tools import get_vault_path
from managers import NordigenSecretManager
from sources.clients.user import User

NORDIGEN_OBTAIN_TOKENS = "https://ob.nordigen.com/api/v2/token/new/"
NORDIGEN_REFRESH_TOKENS = "https://ob.nordigen.com/api/v2/token/refresh/"


class NordigenClient:

    def __init__(self, client: User, **kwargs) -> None:
        self._vault_path: str = get_vault_path() + 'nordigen_secrets.json'
        self.client = client
        self.manager = NordigenSecretManager(salt = client.manager.salt)

        # Tokens
        self._access: str = ""
        self._refresh: str = ""
        self._get_tokens()

    def _get_credentials(self) -> dict[str, str]:
        """
        Get the credentials of the user
        """
        return {"access": self._access, "refresh": self._refresh}

    def _get_tokens(self, mode: str = 'obtain') -> None:
        """
        Get JWT tokens from Nordigen

        Args:
            - mode (str): Mode of the request (refresh, obtain)
        """
        match mode:
            case 'obtain' | 'OBTAIN':
                secrets = self.manager.get_secrets(password = self.client.get_password(self))
                response = requests.post(NORDIGEN_OBTAIN_TOKENS, data = secrets)
                self._access = response.json().get('access')
                self._refresh = response.json().get('refresh')
            case 'refresh' | 'REFRESH':
                response = requests.post(NORDIGEN_REFRESH_TOKENS, data = self._refresh)
                if response.status_code == 401:
                    self._get_tokens(mode = 'obtain')
                    return
                self._access = response.json().get('access')
            case _:
                raise ValueError(f"Mode {mode} is not supported")

    def make_request(self, url: str, data: None | object = None) -> requests.Response:
        """
        Make a request to Nordigen API

        Args:
            - method (str): Method of the request (get, post)
            - url (str): URL of the request
            - data (None | object): Data of the request
        """
        headers = {'Authorization': f'Bearer {self._access}'}
        if data is None:
                response = requests.get(url, headers = headers)
        else:
                response = requests.post(url, headers = headers, data = data)

        # Need refresh
        if response.status_code == 401:
            self._get_tokens(mode = 'refresh')
            return self.make_request(url, data)
        return response

    def country_banks_list(self, country: str) -> list[dict[str, str]]:
        """
        Get the list of banks in a country

        Args:
            - country (str): Country of the banks
        """
        url = f"https://ob.nordigen.com/api/v2/institutions/?country={country}"
        response = self.make_request(url)
        return response.json()


if __name__ == '__main__':
    pwd = 'Xene1xene&'
    user = User()
    try:
        user.create(pwd)
    except FileExistsError:
        user.open(pwd)
    nordigen = NordigenClient(client = user)
