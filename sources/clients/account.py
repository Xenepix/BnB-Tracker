import json
from cryptography.fernet import InvalidToken

from .managers import AccountSecretManager
from tools import get_vault_path


class Account:

    def __init__(self, **kwargs) -> None:
        """
        Build and account

        kwargs:
            - first_name (str):
            - last_name (str):
            - salt_length (int): Length of the salt (default: 64)
        """
        # User data
        self._first_name: str | None = kwargs.get('first_name')
        self._last_name: str | None = kwargs.get('last_name')

        self._vault_path: str = get_vault_path() + 'account_secrets.json'
        self.manager = AccountSecretManager(**kwargs)

    def open(self, password: str) -> dict[str, str]:
        """
        Open the account. User must have a account

        Status:
            - 'success': Account opened
            - 'error': User doesn't have an account
            - 'fail': Password is wrong

        Args:
            - password (str): User password

        Returns:
            - dict[str, str]: Status
        """
        try:
            with open(self._vault_path, 'r') as account_secrets:
                encrypted_salt = json.load(account_secrets).get('salt')
            account_secrets.close()

            try:
                self.manager.decrypt_salt(password, encrypted_salt)
            except InvalidToken:
                return {'fail': 'Password is wrong'}
            if not self.manager.verify_password(password):
                return {'fail': 'Password is wrong'}

        except FileNotFoundError:
            return {'error': 'User doesn\'t have an account'}

        else:
            return {'success': 'Account opened'}



if __name__ == '__main__':
    a = Account(first_name = 'John', last_name = 'Doe')
