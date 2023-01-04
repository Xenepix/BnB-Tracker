import os
import json

from passlib.hash import argon2
from tools import get_project_path


class Account:

    def __init__(self, **kwargs) -> None:
        """
        Build and account

        kwargs:
            - first_name: str
            - last_name: str
        """
        self._first_name: None | str = kwargs.get('first_name')
        self._last_name: None | str = kwargs.get('last_name')

    @staticmethod
    def set_password(self, password: str) -> None:
        """
        Set the password of the account
        """
        salt = os.urandom(16)
        password_hash = argon2.using(salt = salt).hash(password)
        # Save have in the vault
        hash_data = {"salt": salt.hex(),
                     "password": password_hash}
        vault_path = get_project_path() + '/vault/hash.json'
        with open(vault_path, 'w') as vault:
            json.dump(hash_data, vault)
        os.chmod(vault_path, 0o600)
        vault.close()

    @staticmethod
    def verify_password(self, password: str) -> bool:
        """
        Verify the password of the account
        """
        vault_path = get_project_path() + '/vault/hash.json'
        with open(vault_path, 'r') as vault:
            hash_data = json.load(vault)
        vault.close()
        salt = hash_data.get('salt').encode()
        return argon2.using(salt = salt).verify(password, hash_data.get('password'))


if __name__ == '__main__':
    a = Account(first_name = 'John', last_name = 'Doe')
    a.set_password('password')
    print(a.verify_password('password'))
