import json

from .managers import UserSecretManager
from tools import get_vault_path


class User:

    def __init__(self, **kwargs) -> None:
        """
        Build and account

        kwargs:
            - salt_length (int): Length of the salt (default: 64)
        """

        self._vault_path: str = get_vault_path() + 'account_secrets.json'
        self.manager = UserSecretManager(**kwargs)
        self.__password: str | None = None
        self._allowed_transmitters = ['NordigenClient']

    def get_password(self, transmitter: object) -> str:
        """
        Get the password

        Args:
            - transmitter (object): The transmitter that ask for the password
        """
        if self.__password is None:
            raise ValueError('User is not opened')
        if transmitter.__class__.__name__ not in self._allowed_transmitters:
            raise ValueError('Wrong transmitter')
        return self.__password

    def open(self, password: str) -> dict[str, str]:
        """
        Open the account. User must have a account

        Status:
            - 'success': User opened
            - 'error': User doesn't have an account
            - 'fail': Password is wrong

        Args:
            - password (str): User password

        Returns:
            - dict[str, str]: Status
        """
        try:
            res = self.manager.verify_password(password = password)
            if res:
                self.__password = password
                return {'success': 'User opened'}
            else:
                return {'fail': 'Password is wrong'}
        except FileNotFoundError:
            return {'error': 'User doesn\'t have an account'}

    def create(self, password) -> None:
        """
        Create an account
        """
        # Check if the user already have an account
        try:
            with open(self._vault_path, 'r') as account_secrets:
                json.load(account_secrets)
            account_secrets.close()
        except FileNotFoundError:
            self.manager.set_password(password)
            self.__password = password
        else:
            raise FileExistsError('User already have an account')
