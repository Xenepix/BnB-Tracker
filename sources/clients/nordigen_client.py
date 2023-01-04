import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from tools import get_vault_path
from managers import NordigenSecretManager
from sources.clients.user import User


class NordigenClient:

    def __init__(self, client: User, **kwargs) -> None:
        self._vault_path: str = get_vault_path() + 'nordigen_secrets.json'
        self.manager = NordigenSecretManager(client)


if __name__ == '__main__':
    rd_salt = os.urandom(64).hex()
    rd_password = 'password'
    rd_secret_id = 'secret_id'
    rd_secret_key = 'secret_key'

    assert NordigenClient(salt = rd_salt)._generate_key('password') == NordigenClient(salt = rd_salt)._generate_key('password')
    NordigenClient().set_secrets(rd_secret_id, rd_secret_key, rd_password)
    keys = NordigenClient().get_secrets(rd_password)
    assert keys.get('secret_id') == rd_secret_id
    assert keys.get('secret_key') == rd_secret_key
